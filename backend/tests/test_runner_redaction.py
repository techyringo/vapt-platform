from tools.runner import redact_command


def test_redact_command_hides_api_id_env_assignment():
    rendered = redact_command([
        "docker",
        "run",
        "-e",
        "CENSYS_API_ID=censys_example",
        "-e",
        "SHODAN_API_KEY=shodan_example",
        "image",
    ])

    assert "censys_example" not in rendered
    assert "shodan_example" not in rendered
    assert "CENSYS_API_ID=<redacted>" in rendered
    assert "SHODAN_API_KEY=<redacted>" in rendered
