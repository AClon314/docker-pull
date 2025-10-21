"""
Usage:
```python
puller = DockerPull(
    args.image,
    output_path=args.output_path,
    registry_username=args.username,
    registry_password=args.password,
)
puller.save_image(skip=args.skip, keep_tmp=args.verbose)
```
"""

from .docker_pull import (
    DockerImage,
    DockerPull,
)
