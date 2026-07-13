.["@context"] == "https://openvex.dev/ns/v0.2.0"
and (.statements | length == 1)
and .statements[0].vulnerability.name == "CVE-2026-15308"
and .statements[0].status == "not_affected"
and .statements[0].justification == "vulnerable_code_not_in_execute_path"
and (.statements[0].impact_statement | contains("html.parser.HTMLParser"))
and ([.statements[0].products[]["@id"]] | sort) == [
  "extra-codeowners:ci-amd64",
  "extra-codeowners:ci-arm64",
  "extra-codeowners:release-candidate-amd64",
  "extra-codeowners:release-candidate-arm64"
]
and all(
  .statements[0].products[];
  (.subcomponents | length == 1)
  and .subcomponents[0]["@id"] == "pkg:generic/python@3.14.6"
)
