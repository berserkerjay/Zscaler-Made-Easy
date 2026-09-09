# Dictionaries — generated from the pack; predefined Zscaler dictionaries are looked up by name.

resource "zia_dlp_dictionaries" "zbp_python_code_detection" {
  name                         = "ZBP-Python Code Detection"
  description                  = "Detects Python source code by unambiguous Python-only patterns. Trimmed to reduce false positives. [DLP-Check baseline zbp_source_code_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "from\\s+[a-zA-Z_][a-zA-Z0-9_.]*\\s+import\\s+"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "class\\s+[A-Z][a-zA-Z0-9_]*\\s*:"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "def\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*\\(self"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "def\\s+__[a-zA-Z_]+__\\s*\\("
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "#!/usr/bin/python"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "#!/usr/bin/env python"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "if __name__ == '__main__':"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "if __name__ == \"__main__\":"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "def __init__(self"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "raise ValueError("
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "raise TypeError("
  }
}

resource "zia_dlp_dictionaries" "zbp_javascript_code_detection" {
  name                         = "ZBP-JavaScript Code Detection"
  description                  = "Detects JavaScript source code by unambiguous JavaScript-only patterns. Trimmed to reduce false positives. [DLP-Check baseline zbp_source_code_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "=\\s*\\([^)]*\\)\\s*=>\\s*\\{"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "import\\s+.*\\s+from\\s+['\"]"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "export\\s+(default|const|function|class)"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\.forEach\\(\\s*(function|[a-zA-Z_$])"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "class\\s+[A-Z][a-zA-Z0-9_]*\\s*(\\{|extends)"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "function\\s+[a-zA-Z_$][a-zA-Z0-9_$]*\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "this\\.[a-zA-Z_$][a-zA-Z0-9_$]*\\s*="
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "constructor() {"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "module.exports"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "JSON.stringify("
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "JSON.parse("
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "throw new Error("
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "document.querySelector"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "addEventListener("
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "export default"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Promise.resolve("
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "require('"
  }
}

resource "zia_dlp_dictionaries" "zbp_shell_script_detection" {
  name                         = "ZBP-Shell Script Detection"
  description                  = "Detects bash and shell scripts by shebangs and unambiguous shell-only syntax. Trimmed to reduce false positives. [DLP-Check baseline zbp_source_code_baseline v1.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "#!\\s*/bin/(bash|sh|zsh|ksh)"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "#!\\s*/usr/bin/env\\s+(bash|sh|zsh)"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\[\\[\\s+\\$[A-Z_]+\\s+-[gl]t\\s+\\$"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "for\\s+\\w+\\s+in\\s+\\$"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "while\\s+read\\s+\\w+"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "#!/bin/bash"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "#!/bin/sh"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "#!/usr/bin/env bash"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "set -Eeuo pipefail"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "set -euo pipefail"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "echo \"[$(date"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "main \"$@\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = ">> \"$LOG"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "mtime +"
  }
}

