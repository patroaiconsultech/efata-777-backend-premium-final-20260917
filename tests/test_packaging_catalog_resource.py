from importlib.resources import files


def test_agent_catalog_json_is_available_as_package_resource():
    resource = files("orkio_v2.agents").joinpath("catalog_r034.json")
    assert resource.is_file(), "catalog_r034.json must be shipped with the installed package"
    assert resource.read_bytes().strip().startswith(b"{")


def test_pyproject_declares_agent_json_package_data():
    text = open("pyproject.toml", "r", encoding="utf-8").read()
    assert '[tool.setuptools.package-data]' in text
    assert '"orkio_v2.agents" = ["*.json"]' in text
