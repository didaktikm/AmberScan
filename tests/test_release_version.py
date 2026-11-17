"""The image tags stacks start from move with the application version."""

from pathlib import Path

from workbench import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_stack_images_match_the_application_version():
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    maintenance = (ROOT / "compose.maintenance.yaml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    runtime = f"amberdata-workbench:{__version__}-local"
    maintenance_image = f"amberdata-workbench-maintenance:{__version__}-local"
    assert f"image: {runtime}" in compose
    assert f'APP_VERSION: "{__version__}"' in compose
    assert f"image: {maintenance_image}" in maintenance
    assert f'APP_VERSION: "{__version__}"' in maintenance
    assert dockerfile.count(f"ARG APP_VERSION={__version__}") == 2
