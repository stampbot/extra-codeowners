[
    "extra-codeowners:ci-amd64",
    "extra-codeowners:ci-arm64",
    "extra-codeowners:release-candidate-amd64",
    "extra-codeowners:release-candidate-arm64"
  ] as $products
| .["@context"] == "https://openvex.dev/ns/v0.2.0"
and .["@id"] == "https://github.com/stampbot/extra-codeowners/security/vex/python-3.14.6/2"
and .author == "https://github.com/stampbot/extra-codeowners"
and .timestamp == "2026-07-14T00:00:00Z"
and .version == 2
and (.statements | length == 3)
and ([.statements[].vulnerability.name] | sort) == [
  "CVE-2026-11940",
  "CVE-2026-11972",
  "CVE-2026-15308"
]
and all(
  .statements[];
  .status == "not_affected"
  and .justification == "vulnerable_code_not_in_execute_path"
  and ([.products[]["@id"]] | sort) == $products
  and all(
    .products[];
    (.subcomponents | length == 1)
    and .subcomponents[0]["@id"] == "pkg:generic/python@3.14.6"
  )
)
and (
  [
    .statements[]
    | select(.vulnerability.name == "CVE-2026-11940")
    | .impact_statement
  ][0]
  | contains("tarfile.extractall")
)
and (
  [
    .statements[]
    | select(.vulnerability.name == "CVE-2026-11972")
    | .impact_statement
  ][0]
  | contains("streaming mode")
)
and (
  [
    .statements[]
    | select(.vulnerability.name == "CVE-2026-15308")
    | .impact_statement
  ][0]
  | contains("html.parser.HTMLParser")
)
