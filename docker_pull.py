#!/bin/env python
# PYTHON_ARGCOMPLETE_OK
"""
# contarner-pull

This repository contains Python scripts for interacting with Docker Hub or other registries, without needing the Docker client itself. A fork of https://github.com/NotGlop/docker-drag as a module and better CLI interaction.

It relies on the Docker registry [HTTPS API v2](https://docs.docker.com/registry/spec/api/).

Recommand to install `argcomplete aria2p[gui]` for shell tab completion and faster & **resume download**.

## Updates

Fixes from https://github.com/heran226813/docker-drag (centralised request session and retry logic) and https://github.com/lenrys29/docker-drag (authentication for private image registry and Nexus OSS) are included. Also componentise functions and image URL separation for better readability, as well as allowing other scripts to import this file as a module.

## CLI interaction

To use this script, you can run it from the command line with the following arguments:
`python3 contarner_pull.py --username USERNAME --password PASSWORD [registry/][repository/]image[:tag|@digest]" out.tar`

See the full help with `python3 contarner_pull.py --help`.
You may also set the environment variables `REGISTRY_USERNAME` and `REGISTRY_PASSWORD` to avoid typing them in the command line.

## Module import

To use the function, import `DockerPuller` and call `save_image()`:
```py
from contarner_pull import DockerPuller
puller = DockerPuller(image_url, output_path="out.tar", registry_username="", registry_password="")
puller.save_image()
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
from typing import Literal, Self, get_args
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

TYPE_REGISTRY = Literal[
    "registry.k8s.io",
    "registry.gitlab.com",
    "ghcr.io",
    "quay.io",
    "docker.io",
]
REGISTRY = [reg + "/" for reg in get_args(TYPE_REGISTRY)]


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
        session.proxies = {"http": http_proxy, "https": https_proxy}  # type: ignore
        logger.info("[+] Using proxy settings from environment")

    return session


############################################ HELPERS ######################################################


class DockerImageDetails:
    original_url: str
    """Original URL of the Docker image"""
    auth_url: str
    """Authentication URL for Docker Image Registry; should get from image registry"""
    registry_host_url: str = "registry-1.docker.io"
    """Registry URL for Docker Image Registry"""
    repo_name: str
    """Image name without registry and tag"""
    tag: str = "latest"
    """Image tag"""

    json_manifest_type = "application/vnd.docker.distribution.manifest.v2+json"
    json_manifest_type_bis = "application/vnd.docker.distribution.manifest.list.v2+json"

    def __init__(
        self,
        original_url: str,
        auth_url: str,
        registry_host_url: str,
        repo_name: str,
        tag: str,
    ):
        self.original_url: str = original_url
        self.auth_url: str = auth_url
        self.registry_host_url: str = registry_host_url
        self.repo_name: str = repo_name
        self.tag: str = tag

    def get_manifest_url(self, manifest_name: str = "") -> str:
        name = self.tag if not manifest_name else manifest_name
        return f"https://{self.registry_host_url}/v2/{self.repo_name}/manifests/{name}"

    def get_blobs_url(self, digest: str) -> str:
        return f"https://{self.registry_host_url}/v2/{self.repo_name}/blobs/{digest}"

    @property
    def repository_reference(self) -> str:
        """Repository reference (registry and repository) without tag"""
        if self.registry_host_url == self.__class__.registry_host_url:
            return f"{self.repo_name}"
        else:
            return f"{self.registry_host_url}/{self.repo_name}"

    @property
    def fully_qualified_image_name(self) -> str:
        """Fully qualified image name (registry, repository and tag)"""
        return f"{self.repository_reference}:{self.tag}"

    @property
    def image_file_name(self) -> str:
        return self.repo_name.replace("/", "_") + "_" + self.tag + ".tar"

    def get_auth_headers(
        self,
        session: requests.Session,
        username: str = "",
        password: str = "",
    ):
        """Get Docker request authentication token for header.
        This function is useless for unauthenticated registries like Microsoft.

        For registries that allows authenticate with PAT (e.g. Forgejo), you may provide the token explicitly as keyword argument `password="TOKEN"` without a `username`.
        """
        try:
            # setup authentication with username and password
            auth = None
            if username and password != "":
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
            raise

    @staticmethod
    def get_endpoint_registry(
        session: requests.Session, registry_host_url: str, repository: str
    ):
        """Get endpoint registry from url"""
        # default auth url is same as registry url
        server_auth_url = "https://" + registry_host_url + "/v2/"
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
                    assert realm_address is not None  # type check

                    # If Repository is on NEXUS OSS
                    if realm_address.group(1) == "Sonatype Nexus Repository Manager":
                        server_auth_url = "https://" + registry_host_url + "/v2/"
                        logger.debug("[ ] Detected: Nexus OSS repository type")

                    # If Repository is on DockerHub like
                    elif realm_address.group(
                        1
                    ) != registry_host_url and "http" in realm_address.group(1):
                        service = re.search(
                            'service="([^"]*)"', resp.headers["WWW-Authenticate"]
                        )
                        assert service is not None  # type check
                        server_auth_url = f"{realm_address.group(1)}?service={service.group(1)}&scope=repository:{repository}:pull"
                        logger.debug("[ ] Detected: Docker Hub repository type")

                except IndexError:
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
            raise

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
        logger.info(f"Docker image :\t{img}")
        logger.info(f"Docker tag :\t{tag}")
        logger.info(f"Repository :\t{repository}")
        logger.info(f"Server URL :\t{registry_host_url}")
        logger.info(f"Auth endpoint :\t{auth_url}")
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


class DockerPuller:
    """
    Orchestrates downloading a docker image and saving it as a tar archive.

    Args:
        image_url: docker image name in the format of [registry/][repository/]image[:tag|@digest]
        output_path: file path for final tar (if ends not with .tar it will be appended)
        registry_username: registry username (empty string by default)
        registry_password: registry password or PAT (empty string by default)
        session: requests.Session instance. Default uses create_session() result.
    """

    def __init__(
        self,
        image_url: str,
        output_path: str = "",
        registry_username: str = "",
        registry_password: str = "",
        session: requests.Session = create_session(),
    ):
        self.image_url = image_url
        self.output_path = output_path
        self.registry_username = registry_username
        self.registry_password = registry_password
        self.session = session
        self.img_temp_dir = "tmp"
        self.image_details = DockerImageDetails.parse_image_name(
            image_url, self.session
        )
        # placeholder for values filled during flow
        self.manifest_json = {}
        self.confresp_content = b""
        self.fake_layerID = ""

    def save_image(self):
        """High level orchestration; keeps each sub-step in a small method."""
        try:
            if not os.path.exists(self.img_temp_dir):
                logger.debug("[+] Creating temporary directory: %s", self.img_temp_dir)
                os.makedirs(self.img_temp_dir)

            self._fetch_manifest()
            self._download_config()
            self._download_layers()
            self._create_tar_and_cleanup()
            logger.info(
                f"[+] Docker image for {self.image_details.fully_qualified_image_name} is saved to {self.output_path or self.image_details.image_file_name}"
            )
        finally:
            # clean up temp folder no matter what happens
            if os.path.exists(self.img_temp_dir):
                shutil.rmtree(self.img_temp_dir)

    def _fetch_manifest(self):
        logger.info(
            f"[+] Trying to fetch manifest for {self.image_details.fully_qualified_image_name}"
        )
        try:
            resp = self.session.get(
                self.image_details.get_manifest_url(),
                headers=self.image_details.get_auth_headers(
                    self.session, self.registry_username, self.registry_password
                ),
                verify=False,
                timeout=30,
            )
        except requests.exceptions.RequestException as e:
            logger.error("[-] Manifest fetch error: %s", str(e))
            raise

        if resp.status_code != 200:
            logger.error(
                f"[-] Cannot fetch manifest for {self.image_details.registry_host_url} [HTTP {resp.status_code}]"
            )
            logger.error(resp.content)
            raise

        try:
            resp_json = resp.json()
            logger.debug("[+] Response JSON structure:")
            logger.debug(json.dumps(resp_json, indent=2))

            # Handle manifest list (multi-arch images) kept compact
            if "manifests" in resp_json:
                selected_manifest = self._select_manifest(resp_json)
                try:
                    manifest_resp = self.session.get(
                        self.image_details.get_manifest_url(
                            selected_manifest["digest"]
                        ),
                        headers=self.image_details.get_auth_headers(
                            self.session, self.registry_username, self.registry_password
                        ),
                        verify=False,
                        timeout=30,
                    )
                    if manifest_resp.status_code != 200:
                        logger.error(
                            "[-] Failed to fetch specific manifest: %s",
                            manifest_resp.status_code,
                        )
                        logger.error("[-] Response content: %s", manifest_resp.content)
                        raise
                    resp_json = manifest_resp.json()
                    logger.info("[+] Successfully fetched specific manifest")
                except Exception as e:
                    logger.error("[-] Error fetching specific manifest: %s", e)
                    raise

            if "layers" not in resp_json:
                logger.error("[-] Error: No layers found in manifest")
                logger.error("[-] Available keys: %s", list(resp_json.keys()))
                raise

            self.manifest_json = resp_json

        except KeyError as e:
            logger.error("[-] Error: Could not find required key in response: %s", e)
            logger.error("[-] Available keys: %s", list(resp_json.keys()))
            raise
        except Exception as e:
            logger.error("[-] Unexpected error: %s", e)
            raise

    def _select_manifest(self, resp_json: dict) -> dict:
        logger.debug("[+] This is a multi-arch image. Scanning manifests")
        # choose linux/amd64 first, fallback windows/amd64, else first
        selected = None
        for m in resp_json["manifests"]:
            platform = m.get("platform", {})
            if (
                platform.get("os") == "linux"
                and platform.get("architecture") == "amd64"
            ):
                selected = m
                break
        if not selected:
            for m in resp_json["manifests"]:
                platform = m.get("platform", {})
                if (
                    platform.get("os") == "windows"
                    and platform.get("architecture") == "amd64"
                ):
                    selected = m
                    break
        if not selected:
            selected = resp_json["manifests"][0]
        logger.info(
            "[+] Selected platform: %s/%s",
            selected.get("platform", {}).get("os", "unknown"),
            selected.get("platform", {}).get("architecture", "unknown"),
        )
        return selected

    def _download_config(self):
        config_digest = self.manifest_json["config"]["digest"]
        try:
            confresp = self.session.get(
                self.image_details.get_blobs_url(config_digest),
                headers=self.image_details.get_auth_headers(
                    self.session, self.registry_username, self.registry_password
                ),
                verify=False,
                timeout=30,
            )
        except requests.exceptions.RequestException as e:
            logger.error("[-] Config fetch error: %s", str(e))
            raise
        self.confresp_content = confresp.content
        with open(f"{self.img_temp_dir}/{config_digest[7:]}.json", "wb") as file:
            file.write(self.confresp_content)

        # create base manifest file content list
        self._manifest_content = [
            {
                "Config": config_digest[7:] + ".json",
                "RepoTags": [self.image_details.fully_qualified_image_name],
                "Layers": [],
            }
        ]

    def _compute_fake_layerID(self, parentid: str, ublob: str) -> str:
        """Compute fake layer id from parentid and digest."""
        return hashlib.sha256(
            (parentid + "\n" + ublob + "\n").encode("utf-8")
        ).hexdigest()

    def _prepare_layer_dir(self, fake_layerID: str) -> str:
        """Create directory for a layer and write VERSION file."""
        layerdir = os.path.join(self.img_temp_dir, fake_layerID)
        os.makedirs(layerdir, exist_ok=True)
        with open(os.path.join(layerdir, "VERSION"), "w") as f:
            f.write("1.0")
        return layerdir

    def _fetch_layer_response(self, layer: dict, ublob: str) -> requests.Response:
        """Fetch layer content (primary blob URL then fallback to layer['urls'][0])."""
        try:
            bresp = self.session.get(
                self.image_details.get_blobs_url(ublob),
                headers=self.image_details.get_auth_headers(
                    self.session, self.registry_username, self.registry_password
                ),
                stream=True,
                verify=False,
                timeout=30,
            )
        except requests.exceptions.RequestException as e:
            logger.error("[-] Layer fetch error: %s", str(e))
            raise

        if bresp.status_code != 200:
            # fallback to layer["urls"][0] if provided
            fallback_url = None
            if isinstance(layer.get("urls"), list) and layer["urls"]:
                fallback_url = layer["urls"][0]
            if fallback_url:
                try:
                    bresp = self.session.get(
                        fallback_url,
                        headers=self.image_details.get_auth_headers(
                            self.session, self.registry_username, self.registry_password
                        ),
                        stream=True,
                        verify=False,
                        timeout=30,
                    )
                except requests.exceptions.RequestException as e:
                    logger.error("[-] Layer fetch error: %s", str(e))
                    raise
            if bresp.status_code != 200:
                logger.error(
                    "[-] ERROR: Cannot download layer %s [HTTP %s]",
                    ublob[7:19],
                    bresp.status_code,
                )
                logger.error(bresp.content)
                raise
        return bresp

    def _stream_save_gzip(
        self, bresp: requests.Response, gzip_path: str, ublob: str
    ) -> None:
        """Stream response content into gzip_path while updating the progress bar."""
        try:
            bresp.raise_for_status()
        except Exception as e:
            logger.error("[-] Layer stream error: %s", e)
            raise

        content_length = int(bresp.headers.get("Content-Length", "0"))
        unit = content_length / 50 if content_length else 1
        acc = 0
        nb_traits = 0
        progress_bar(ublob, nb_traits)
        with open(gzip_path, "wb") as file:
            for chunk in bresp.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)
                    acc += len(chunk)
                    if acc > unit:
                        nb_traits += 1
                        progress_bar(ublob, nb_traits)
                        acc = 0

    def _decompress_layer(self, gzip_path: str, layerdir: str, ublob: str) -> None:
        """Decompress gzip_path into layer.tar inside layerdir and remove gzip file."""
        sys.stdout.write(f"\r{ublob[7:19]}: Extracting...{' ' * 50}")
        sys.stdout.flush()
        with open(os.path.join(layerdir, "layer.tar"), "wb") as out_f:
            with gzip.open(gzip_path, "rb") as unzLayer:
                shutil.copyfileobj(unzLayer, out_f)
        try:
            os.remove(gzip_path)
        except Exception:
            # don't block on cleanup failure
            logger.debug("[-] Failed to remove temporary gzip file: %s", gzip_path)

    def _build_and_write_layer_json(
        self,
        layer: dict,
        is_last: bool,
        fake_layerID: str,
        parentid: str,
        empty_json: str,
        layerdir: str,
    ) -> str:
        """
        Build the layer json structure and write to file.
        Returns the new parentid (which equals fake_layerID).
        """
        if is_last:
            json_obj = json.loads(self.confresp_content)
            # attempt to remove keys similar to original behavior
            if "history" in json_obj:
                del json_obj["history"]
            try:
                del json_obj["rootfs"]
            except Exception:
                try:
                    del json_obj["rootfS"]
                except Exception:
                    pass
        else:
            json_obj = json.loads(empty_json)

        json_obj["id"] = fake_layerID
        if parentid:
            json_obj["parent"] = parentid

        with open(os.path.join(layerdir, "json"), "w") as jf:
            jf.write(json.dumps(json_obj))

        return json_obj["id"]

    def _download_layers(self):
        """High-level loop over manifest layers delegating to helper methods."""
        layers = self.manifest_json["layers"]
        empty_json = '{"created":"1970-01-01T00:00:00Z","container_config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false, \
            "AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false, "StdinOnce":false,"Env":null,"Cmd":null,"Image":"", \
            "Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null}}'

        parentid = ""
        for layer in layers:
            ublob = layer["digest"]
            fake_layerID = self._compute_fake_layerID(parentid, ublob)
            layerdir = self._prepare_layer_dir(fake_layerID)
            gzip_path = os.path.join(layerdir, "layer_gzip.tar")

            # Download layer (stream)
            sys.stdout.write(ublob[7:19] + ": Downloading...")
            sys.stdout.flush()
            bresp = self._fetch_layer_response(layer, ublob)
            # try:
            #     dl_by_aria2(
            #         bresp.url,
            #         gzip_path,
            #         headers=self.image_details.get_auth_headers(
            #             self.session, self.registry_username, self.registry_password
            #         ),
            #     )
            #     continue
            # except Exception as e:
            #     logger.error("[-] Failed to download layer %s: %s", ublob[7:19], e)

            self._stream_save_gzip(bresp, gzip_path, ublob)
            self._decompress_layer(gzip_path, layerdir, ublob)

            logger.info(
                "\r%s: Pull complete [%s]\r",
                ublob[7:19],
                bresp.headers.get("Content-Length"),
            )
            self._manifest_content[0]["Layers"].append(fake_layerID + "/layer.tar")

            # Create layer json and update parentid
            is_last = layers[-1]["digest"] == layer["digest"]
            parentid = self._build_and_write_layer_json(
                layer, is_last, fake_layerID, parentid, empty_json, layerdir
            )

            # record last fake id for repositories mapping
            self.fake_layerID = fake_layerID

    def _create_tar_and_cleanup(self):
        # manifest.json
        with open(os.path.join(self.img_temp_dir, "manifest.json"), "w") as mf:
            mf.write(json.dumps(self._manifest_content))

        content = {
            self.image_details.repository_reference: {
                self.image_details.tag: self.fake_layerID
            }
        }
        with open(os.path.join(self.img_temp_dir, "repositories"), "w") as rf:
            rf.write(json.dumps(content))

        logger.info("[=] Creating archive...")
        out_path = self.output_path or self.image_details.image_file_name
        if not str(out_path).endswith(".tar"):
            out_path = str(out_path) + ".tar"
        with tarfile.open(out_path, "w") as tar:
            tar.add(self.img_temp_dir, arcname=os.path.sep)
        self.output_path = out_path


def dl_by_aria2(
    url: str,
    out_path: str,
    headers: dict | None = None,
    aria2_host: str = "http://localhost",
    aria2_port: int = 6800,
    aria2_secret: str = "",
    timeout: int = 300,
):
    """
    Use aria2 RPC (aria2p) to download `url` into `out_path`. Waits until download completes.
    Raises RuntimeError on failure.
    """
    try:
        import aria2p
    except Exception as e:
        raise RuntimeError("aria2p not installed") from e

    client = aria2p.Client(host=aria2_host, port=aria2_port, secret=aria2_secret)
    api = aria2p.API(client=client)

    options: dict = {}
    # aria2 options: set directory and output filename
    out_dir = os.path.dirname(out_path) or "."
    options["dir"] = out_dir
    options["out"] = os.path.basename(out_path)

    if headers:
        # convert dict -> list of "Header: value"
        hdrs = [f"{k}: {v}" for k, v in headers.items()]
        options["header"] = hdrs

    # add uri and start download
    download = api.add_uris([url], options=options)

    # wait loop (poll)
    import time

    start = time.time()
    while True:
        # refresh download state
        d = api.get_download(download.gid)
        if d.is_complete:
            # success
            local = os.path.join(out_dir, options["out"])
            if not os.path.exists(local):
                raise RuntimeError(
                    f"aria2 reported complete, but file not found: {local}"
                )
            return local
        if d.error_code:
            raise RuntimeError(
                f"aria2 download failed: {d.error_message} (gid={d.gid})"
            )
        if time.time() - start > timeout:
            raise RuntimeError(
                f"aria2 download timeout after {timeout}s for gid={download.gid}"
            )
        time.sleep(0.5)


def parse_arg():
    parser = argparse.ArgumentParser(
        description="Pull a Docker image and save it as a tar archive."
    )
    action = parser.add_argument(
        "image",
        help="docker image name in the format of [registry/][repository/]image[:tag|@digest]",
    )
    action.completer = lambda prefix, **kwargs: REGISTRY  # type: ignore
    parser.add_argument(
        "output_path", nargs="?", help="output path for the image tar", default=""
    )
    parser.add_argument(
        "--username",
        "-u",
        help="container registry username",
        default=os.getenv("REGISTRY_USERNAME", ""),
    )
    parser.add_argument(
        "--password",
        "-p",
        help="container registry password. Pass PAT to this parameter without --username if you are using a Personal Access Token (PAT)",
        default=os.getenv("REGISTRY_PASSWORD", ""),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="set logging level (default: INFO)",
    )
    try:
        import argcomplete

        argcomplete.autocomplete(parser)
    except ImportError:
        ...
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_arg()
    logging.basicConfig(level=args.verbose)
    logger.setLevel(args.verbose)
    try:
        puller = DockerPuller(
            args.image,
            output_path=args.output_path,
            registry_username=args.username,
            registry_password=args.password,
        )
        puller.save_image()
    except KeyboardInterrupt:
        logger.warning("[-] Interrupted by user")
        exit(1)
