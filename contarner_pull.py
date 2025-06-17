"""
# contarner-pull

This repository contains Python scripts for interacting with Docker Hub or other registries, without needing the Docker client itself. A fork of https://github.com/NotGlop/docker-drag as a module and better CLI interaction.

It relies on the Docker registry [HTTPS API v2](https://docs.docker.com/registry/spec/api/).

## Updates

Fixes from https://github.com/heran226813/docker-drag (centralised request session and retry logic) and https://github.com/lenrys29/docker-drag (authentication for private image registry and Nexus OSS) are included. Also componentise functions and image URL separation for better readability, as well as allowing other scripts to import this file as a module.

## CLI interaction

To use this script, you can run it from the command line with the following arguments:
`python3 contarner_pull.py --username USERNAME --password PASSWORD [registry/][repository/]image[:tag|@digest]" out.tar`

See the full help with `python3 contarner_pull.py --help`.

## Module import

To use the function, import `save_docker_image()` and pass in the necessary arguments.
```py
from contarner_pull import save_docker_image
save_docker_image(image_url, output_path, username, password)
```

## License

Released under GNU General Public License v3.0 as `docker-drag`.
"""

import os
import sys
import gzip
import json
import hashlib
import shutil
from typing import Self
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import tarfile
import urllib3
import re
import logging
import argparse

urllib3.disable_warnings()

# Configure logging
logger = logging.getLogger(__name__)


def create_session() -> requests.Session:
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Check if proxy environment variables are set
    http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")

    if http_proxy or https_proxy:
        session.proxies = {"http": http_proxy, "https": https_proxy}
        logger.info("[+] Using proxy settings from environment")

    return session


############################################ HELPERS ######################################################


class DockerImageDetails:
    original_url = None
    """Original URL of the Docker image"""
    auth_url = None
    """Authentication URL for Docker Image Registry; should get from image registry"""
    registry_host_url = "registry-1.docker.io"
    """Registry URL for Docker Image Registry"""
    repo_name = None
    """Image name without registry and tag"""
    tag = "latest"
    """Image tag"""

    json_manifest_type = "application/vnd.docker.distribution.manifest.v2+json"
    json_manifest_type_bis = "application/vnd.docker.distribution.manifest.list.v2+json"

    def __init__(
        self,
        original_url: str,
        auth_url: str = None,
        registry_host_url: str = None,
        repo_name: str = None,
        tag: str = None,
    ):
        self.original_url = original_url
        self.auth_url = auth_url
        self.registry_host_url = registry_host_url
        self.repo_name = repo_name
        self.tag = tag

    def get_manifest_url(self, manifest_name: str = None):
        if manifest_name is None:
            manifest_name = self.tag
        return f"https://{self.registry_host_url}/v2/{self.repo_name}/manifests/{manifest_name}"

    def get_blobs_url(self, digest: str):
        return f"https://{self.registry_host_url}/v2/{self.repo_name}/blobs/{digest}"

    @property
    def repository_reference(self):
        """Repository reference (registry and repository) without tag"""
        if self.registry_host_url == self.__class__.registry_host_url:
            return f"{self.repo_name}"
        else:
            return f"{self.registry_host_url}/{self.repo_name}"

    @property
    def fully_qualified_image_name(self):
        """Fully qualified image name (registry, repository and tag)"""
        return f"{self.repository_reference}:{self.tag}"

    @property
    def image_file_name(self):
        return self.repo_name.replace("/", "_") + "_" + self.tag + ".tar"

    def get_auth_headers(
        self, session: requests.Session, username: str = None, password: str = None
    ):
        """Get Docker request authentication token for header.
        This function is useless for unauthenticated registries like Microsoft.
        
        For registries that allows authenticate with PAT (e.g. Forgejo), you may provide the token explicitly as keyword argument `password="TOKEN"` without a `username`.
        """
        try:
            # setup authentication with username and password
            auth = None
            if password is not None:
                # username might be None for PAT
                auth = (username, password)
            
            resp = session.get(self.auth_url, verify=False, timeout=30, auth=auth)
            if resp.status_code != 200:
                # authentication failed or user error
                raise requests.exceptions.RequestException(
                    f"{resp.status_code}: {resp.content.decode()}",
                    request=resp.request,
                    response=resp,
                )
            access_token = resp.json()["token"]
            auth_head = {
                "Authorization": "Bearer " + access_token,
                "Accept": f"{self.json_manifest_type},{self.json_manifest_type_bis}",
            }
            return auth_head
        except requests.exceptions.RequestException as e:
            logger.error(f"[-] Authentication error: {e}")
            exit(1)

    @staticmethod
    def get_endpoint_registry(
        session: requests.Session, registry_host_url: str, repository: str
    ):
        """Get endpoint registry from url"""
        try:
            logger.info(f"[+] Connecting to registry: {registry_host_url}")
            resp = session.get(
                f"https://{registry_host_url}/v2/", verify=False, timeout=30
            )
            if resp.status_code == 401:
                try:
                    realm_address = re.search(
                        'realm="([^"]*)"', resp.headers["WWW-Authenticate"]
                    )

                    # If Repository is on NEXUS OSS
                    if realm_address.group(1) == "Sonatype Nexus Repository Manager":
                        server_auth_url = "https://" + registry_host_url + "/v2/"
                        logger.debug("[ ] Detected: Nexus OSS repository type")

                    # If Repository is on DockerHub like
                    if realm_address.group(
                        1
                    ) != registry_host_url and "http" in realm_address.group(1):
                        service = re.search(
                            'service="([^"]*)"', resp.headers["WWW-Authenticate"]
                        )
                        server_auth_url = f"{realm_address.group(1)}?service={service.group(1)}&scope=repository:{repository}:pull"
                        logger.debug("[ ] Detected: Docker Hub repository type")

                except IndexError:
                    server_auth_url = "https://" + registry_host_url + "/v2/"
                    logger.info(
                        "[-] Failed to fetch authentication endpoint info from registry, using registry URL"
                    )

            return server_auth_url
        except requests.exceptions.RequestException as e:
            logger.error("[-] Connection error:", str(e))
            logger.error("[*] Troubleshooting tips:")
            logger.error("    1. Check your internet connection")
            logger.error(
                "    2. If you are behind a proxy, set HTTP_PROXY and HTTPS_PROXY environment variables"
            )
            logger.error("    3. Try using a VPN if the registry is blocked")
            logger.error(
                f"    4. Verify if the registry {registry_host_url} is accessible from your network"
            )
            exit(1)

    @classmethod
    def parse_image_name(cls, image_name: str, session: requests.Session) -> Self:
        img = None
        tag = cls.tag
        registry_host_url = cls.registry_host_url

        # Look for the Docker image to download
        imgparts = image_name.split("/")
        try:
            img, tag = imgparts[-1].split("@")
        except ValueError:
            try:
                img, tag = imgparts[-1].split(":")
            except ValueError:
                img = imgparts[-1]

        # Docker client doesn't seem to consider the first element as a potential registry unless there is a '.' or ':'
        if len(imgparts) > 1 and ("." in imgparts[0] or ":" in imgparts[0]):
            registry_host_url = imgparts[0]
            repo_without_last = "/".join(imgparts[1:-1])
        else:
            if len(imgparts[:-1]) != 0:
                repo_without_last = "/".join(imgparts[:-1])
            else:
                repo_without_last = "library"
        repository = f"{repo_without_last}/{img}"

        auth_url = cls.get_endpoint_registry(session, registry_host_url, repository)

        logger.info("_" * 50)
        logger.info("Docker image :\t" + img)
        logger.info("Docker tag :\t" + tag)
        logger.info("Repository :\t" + repository)
        logger.info("Server URL :\t" + registry_host_url)
        logger.info("Auth endpoint :\t" + auth_url)
        logger.info("_" * 50)

        return cls(
            original_url=image_name,
            auth_url=auth_url,
            registry_host_url=registry_host_url,
            repo_name=repository,
            tag=tag,
        )


# Docker style progress bar
def progress_bar(ublob, nb_traits):
    sys.stdout.write("\r" + ublob[7:19] + ": Downloading [")
    for i in range(0, nb_traits):
        if i == nb_traits - 1:
            sys.stdout.write(">")
        else:
            sys.stdout.write("=")
    for i in range(0, 49 - nb_traits):
        sys.stdout.write(" ")
    sys.stdout.write("]")
    sys.stdout.flush()


############################################## MAIN ########################################################


def save_docker_image(
    image_url: str,
    output_path: str | os.PathLike,
    registry_username: str = None,
    registry_password: str = None,
    session: requests.Session = None,
):
    """
    Downloads a Docker image from a remote registry and saves it as a tar archive.

    Parameters
    ----------
    image_url : str
        The Docker image URL or identifier.
    output_path : str or os.PathLike
        The file path where the Docker image tar archive will be saved.
        The file extension will be automatically set to '.tar' if not match.
    registry_username : str, optional
        Username for authenticating with the Docker registry. Defaults to None.
    registry_password : str, optional
        Password for authenticating with the Docker registry. Defaults to None.
        Pass PAT to this parameter without `registry_username` if you are using a Personal Access Token (PAT).
    session : requests.Session, optional
        A pre-configured `requests.Session` for HTTP requests. If not provided,
        a new session is created internally.

    Raises
    ------
    SystemExit
        Exits the process (using `exit(1)`) on encountering network errors,
        missing manifest data, or file operation failures.

    Notes
    -----
    - HTTPS certificate verification is disabled (`verify=False`) for all HTTP requests.
    - The function uses a temporary directory ("tmp") during processing which is cleaned up in all cases.
    - The method of generating fake layer IDs is simplistic and may not match Docker's actual layer ID generation.
    """


    if session is None:
        session = create_session()

    image_details = DockerImageDetails.parse_image_name(image_url, session)

    img_temp_dir = "tmp"

    try:
        # Create tmp directory if it doesn't exist
        if not os.path.exists(img_temp_dir):
            logger.debug("[+] Creating temporary directory:", img_temp_dir)
            os.makedirs(img_temp_dir)

        ############## Fetch manifest v2 and get image layer digests

        logger.info(
            f"[+] Trying to fetch manifest for {image_details.fully_qualified_image_name}"
        )
        try:
            resp = session.get(
                image_details.get_manifest_url(),
                headers=image_details.get_auth_headers(
                    session, registry_username, registry_password
                ),
                verify=False,
                timeout=30,
            )
        except requests.exceptions.RequestException as e:
            logger.error("[-] Manifest fetch error:", str(e))
            exit(1)
        logger.debug("[+] Response status code:", resp.status_code)
        logger.debug("[+] Response headers:", resp.headers)

        if resp.status_code != 200:
            logger.error(
                f"[-] Cannot fetch manifest for {image_details.registry_host_url} [HTTP {resp.status_code}]"
            )
            logger.error(resp.content)
            exit(1)

        content_type = resp.headers.get("content-type", "")
        logger.debug("[+] Content type:", content_type)

        try:
            resp_json = resp.json()
            logger.debug("[+] Response JSON structure:")
            logger.debug(json.dumps(resp_json, indent=2))

            # Handle manifest list (multi-arch images)
            if "manifests" in resp_json:
                logger.debug("[+] This is a multi-arch image. Available platforms:")
                for m in resp_json["manifests"]:
                    if "platform" in m:
                        logger.debug(
                            "    - {}/{} ({})".format(
                                m["platform"].get("os", "unknown"),
                                m["platform"].get("architecture", "unknown"),
                                m["digest"],
                            )
                        )

                # Try to find linux/amd64 platform first, then fall back to windows/amd64
                selected_manifest = None
                for m in resp_json["manifests"]:
                    platform = m.get("platform", {})
                    if (
                        platform.get("os") == "linux"
                        and platform.get("architecture") == "amd64"
                    ):
                        selected_manifest = m
                        break

                if not selected_manifest:
                    for m in resp_json["manifests"]:
                        platform = m.get("platform", {})
                        if (
                            platform.get("os") == "windows"
                            and platform.get("architecture") == "amd64"
                        ):
                            selected_manifest = m
                            break

                if not selected_manifest:
                    # If no preferred platform found, use the first one
                    selected_manifest = resp_json["manifests"][0]

                logger.info(
                    "[+] Selected platform: {}/{}".format(
                        selected_manifest["platform"].get("os", "unknown"),
                        selected_manifest["platform"].get("architecture", "unknown"),
                    )
                )

                # Fetch the specific manifest
                try:
                    manifest_resp = session.get(
                        image_details.get_manifest_url(selected_manifest["digest"]),
                        headers=image_details.get_auth_headers(
                            session, registry_username, registry_password
                        ),  # get a fresh token
                        verify=False,
                        timeout=30,
                    )
                    if manifest_resp.status_code != 200:
                        logger.error(
                            "[-] Failed to fetch specific manifest:",
                            manifest_resp.status_code,
                        )
                        logger.error("[-] Response content:", manifest_resp.content)
                        exit(1)
                    resp_json = manifest_resp.json()
                    logger.info("[+] Successfully fetched specific manifest")
                except Exception as e:
                    logger.error("[-] Error fetching specific manifest:", e)
                    exit(1)

            # Now we should have the actual manifest with layers
            if "layers" not in resp_json:
                logger.error("[-] Error: No layers found in manifest")
                logger.error("[-] Available keys:", list(resp_json.keys()))
                exit(1)

            layers = resp_json["layers"]

        except KeyError as e:
            logger.error("[-] Error: Could not find required key in response:", e)
            logger.error("[-] Available keys:", list(resp_json.keys()))
            exit(1)
        except Exception as e:
            logger.error("[-] Unexpected error:", e)
            exit(1)

        # download digest to temp folder
        config = resp_json["config"]["digest"]
        try:
            confresp = session.get(
                image_details.get_blobs_url(config),
                headers=image_details.get_auth_headers(
                    session, registry_username, registry_password
                ),  # get a fresh token
                verify=False,
                timeout=30,
            )
        except requests.exceptions.RequestException as e:
            logger.error("[-] Config fetch error:", str(e))
            exit(1)
        file = open("{}/{}.json".format(img_temp_dir, config[7:]), "wb")
        file.write(confresp.content)
        file.close()

        content = [
            {
                "Config": config[7:] + ".json",
                "RepoTags": [image_details.fully_qualified_image_name],
                "Layers": [],
            }
        ]

        empty_json = '{"created":"1970-01-01T00:00:00Z","container_config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false, \
            "AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false, "StdinOnce":false,"Env":null,"Cmd":null,"Image":"", \
            "Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null}}'

        # Build layer folders
        parentid = ""
        for layer in layers:
            ublob = layer["digest"]
            # FIXME: Creating fake layer ID. Don't know how Docker generates it
            fake_layerid = hashlib.sha256(
                (parentid + "\n" + ublob + "\n").encode("utf-8")
            ).hexdigest()
            layerdir = img_temp_dir + "/" + fake_layerid
            os.mkdir(layerdir)

            # Creating VERSION file
            file = open(layerdir + "/VERSION", "w")
            file.write("1.0")
            file.close()

            # Creating layer.tar file
            sys.stdout.write(ublob[7:19] + ": Downloading...")
            sys.stdout.flush()
            try:
                bresp = session.get(
                    image_details.get_blobs_url(ublob),
                    headers=image_details.get_auth_headers(
                        session, registry_username, registry_password
                    ),  # get a fresh token
                    stream=True,
                    verify=False,
                    timeout=30,
                )
            except requests.exceptions.RequestException as e:
                logger.error("[-] Layer fetch error:", str(e))
                exit(1)
            if bresp.status_code != 200:  # When the layer is located at a custom URL
                try:
                    bresp = session.get(
                        layer["urls"][0],
                        headers=image_details.get_auth_headers(
                            session, registry_username, registry_password
                        ),  # get a fresh token
                        stream=True,
                        verify=False,
                        timeout=30,
                    )
                except requests.exceptions.RequestException as e:
                    logger.error("[-] Layer fetch error:", str(e))
                    exit(1)
                if bresp.status_code != 200:
                    logger.error(
                        "[-] ERROR: Cannot download layer {} [HTTP {}]".format(
                            ublob[7:19],
                            bresp.status_code,
                            bresp.headers["Content-Length"],
                        )
                    )
                    logger.error(bresp.content)
                    exit(1)
            # Stream download and follow the progress
            bresp.raise_for_status()
            unit = int(bresp.headers["Content-Length"]) / 50
            acc = 0
            nb_traits = 0
            progress_bar(ublob, nb_traits)
            with open(layerdir + "/layer_gzip.tar", "wb") as file:
                for chunk in bresp.iter_content(chunk_size=8192):
                    if chunk:
                        file.write(chunk)
                        acc = acc + 8192
                        if acc > unit:
                            nb_traits = nb_traits + 1
                            progress_bar(ublob, nb_traits)
                            acc = 0
            sys.stdout.write(
                f"\r{ublob[7:19]}: Extracting...{' ' * 50}"
            )  # Ugly but works everywhere
            sys.stdout.flush()
            with open(
                layerdir + "/layer.tar", "wb"
            ) as file:  # Decompress gzip response
                unzLayer = gzip.open(layerdir + "/layer_gzip.tar", "rb")
                shutil.copyfileobj(unzLayer, file)
                unzLayer.close()
            os.remove(layerdir + "/layer_gzip.tar")
            logger.info(
                f"\r{ublob[7:19]}: Pull complete [{(bresp.headers["Content-Length"])}]\r"
            )
            content[0]["Layers"].append(fake_layerid + "/layer.tar")

            # Creating json file
            file = open(layerdir + "/json", "w")
            # last layer = config manifest - history - rootfs
            if layers[-1]["digest"] == layer["digest"]:
                # FIXME: json.loads() automatically converts to unicode, thus decoding values whereas Docker doesn't
                json_obj = json.loads(confresp.content)
                del json_obj["history"]
                try:
                    del json_obj["rootfs"]
                except:  # Because Microsoft loves case insensitiveness
                    del json_obj["rootfS"]
            else:  # other layers json are empty
                json_obj = json.loads(empty_json)
            json_obj["id"] = fake_layerid
            if parentid:
                json_obj["parent"] = parentid
            parentid = json_obj["id"]
            file.write(json.dumps(json_obj))
            file.close()

        file = open(img_temp_dir + "/manifest.json", "w")
        file.write(json.dumps(content))
        file.close()

        content = {
            image_details.repository_reference: {image_details.tag: fake_layerid}
        }
        file = open(img_temp_dir + "/repositories", "w")
        file.write(json.dumps(content))
        file.close()

        # Create image tar from temp folder and clean tmp directory
        logger.info("[=] Creating archive...")
        if not output_path:
            output_path = image_details.image_file_name
        if not output_path.endswith(".tar"):
            output_path = str(output_path) + ".tar"
        tar = tarfile.open(output_path, "w")
        tar.add(img_temp_dir, arcname=os.path.sep)
        tar.close()
        logger.info(
            f"[+] Docker image for {image_details.fully_qualified_image_name} is saved to {output_path}"
        )

    finally:
        # clean up temp folder no matter what happens
        if os.path.exists(img_temp_dir):
            shutil.rmtree(img_temp_dir)


if __name__ == "__main__":

    ############## Parse arguments ##############

    parser = argparse.ArgumentParser(
        description="Pull a Docker image and save it as a tar archive."
    )
    parser.add_argument("image", help="docker image name in the format of [registry/][repository/]image[:tag|@digest]")
    parser.add_argument(
        "output_path", nargs="?", help="output path for the image tar", default=None
    )
    parser.add_argument(
        "--username",
        "-u",
        help="container registry username",
        default=os.getenv("REGISTRY_USERNAME"),
    )
    parser.add_argument(
        "--password",
        "-p",
        help="container registry password. Pass PAT to this parameter without --username if you are using a Personal Access Token (PAT)",
        default=os.getenv("REGISTRY_PASSWORD"),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="set logging level (default: INFO)",
    )

    args = parser.parse_args()
    logging.basicConfig(level=args.verbose)
    logger.setLevel(args.verbose)

    save_docker_image(args.image, args.output_path, args.username, args.password)
