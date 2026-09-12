# Dictionaries — generated from the pack; predefined Zscaler dictionaries are looked up by name.

data "zia_dlp_dictionaries" "cred_leakage" {
  name = "CRED_LEAKAGE"
}

resource "zia_dlp_dictionaries" "src_csharp_signal" {
  name                         = "SRC-CSharp Signal"
  description                  = "C# (C-Sharp) syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\busing\\b\\s+(?:System|Microsoft|Newtonsoft|Azure|Amazon|Google)(?:\\.[A-Z][A-Za-z0-9]+)*\\s*;"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bnamespace\\b\\s+[A-Z][A-Za-z0-9_]*(?:\\.[A-Z][A-Za-z0-9_]+)*\\s*\\{?"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\b(?:public|private|protected|static|abstract)\\b\\s+){0,2}\\b(?:internal|sealed|partial)\\b(?:\\s+\\w+){0,2}\\s+\\b(?:class|interface|struct|enum|record)\\b\\s+[A-Z]|^\\s*(?:\\bpublic\\b\\s+)?\\binterface\\b\\s+I[A-Z]\\w*|^\\s*\\bclass\\b\\s+[A-Z]\\w*\\s*:\\s*I[A-Z]\\w*"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\b(?:public|private|protected|internal)\\s+)?(?:\\bstatic\\s+)?(?:\\basync\\s+)?(?:\\b(?:override|virtual|abstract|sealed)\\s+)?\\b(?:Task|ValueTask|I[A-Z]\\w*|void|string|int|bool|double|decimal|long|object)(?:<[^>]+>)?(?:\\?)?\\s+[A-Z]\\w*\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bConsole\\.(?:WriteLine|Write|ReadLine|ReadKey)\\b\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bString\\.(?:Format|IsNullOrEmpty|IsNullOrWhiteSpace|Join|Split)\\b\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bthrow\\b\\s+\\bnew\\b\\s+(?:ArgumentNull|ArgumentOutOfRange|Argument|InvalidOperation|NotImplemented|NotSupported|ObjectDisposed|InvalidCast|FormatException|UnauthorizedAccess|FileNotFound|HttpRequest|TaskCanceled|Timeout)Exception\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\[\\b(?:HttpGet|HttpPost|HttpPut|HttpDelete|Route|Serializable|Authorize|FromBody|Required|JsonProperty|Test|Fact)\\b(?:\\s*\\([^)]*\\))?\\]"
  }
}

resource "zia_dlp_dictionaries" "src_csharp_anchor" {
  name                         = "SRC-CSharp Anchor"
  description                  = "C# (C-Sharp) structural fingerprint (v4.14): C# file structure: using-directives OR namespace declaration [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\busing\\b\\s+(?:System|Microsoft|Newtonsoft|Azure|Amazon|Google)(?:\\.[A-Z]\\w*)*\\s*;|^\\s*\\bnamespace\\b\\s+[A-Z][\\w.]*\\s*[\\{;]"
  }
}

resource "zia_dlp_dictionaries" "src_cplusplus_signal" {
  name                         = "SRC-CPlusPlus Signal"
  description                  = "C++ syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*#\\s*include\\s*[<\"][a-zA-Z0-9_./]{1,200}[>\"]"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\busing\\b\\s+\\bnamespace\\b\\s+[a-zA-Z_][a-zA-Z0-9_:]*\\s*;"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bclass\\b\\s+[A-Z][A-Za-z0-9_]*(?:\\s*:\\s*\\b(?:public|private|protected)\\b\\s+[A-Z][A-Za-z0-9_:<>,\\s]*)?\\s*\\{"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\btemplate\\b\\s*<\\s*\\b(?:typename|class)\\b\\s+[A-Z]\\w*"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bvirtual\\b\\s+[\\w:&*<>]+\\s+[a-zA-Z_]\\w*\\s*\\(|\\boverride\\b\\s*[;{=)]|=\\s*0\\s*;"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:cout|cerr|clog)\\b\\s*<<|\\bcin\\b\\s*>>|\\bendl\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:std::)?\\b(?:unique_ptr|shared_ptr|weak_ptr|make_unique|make_shared)\\b\\s*<"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bcatch\\b\\s*\\(\\s*(?:\\bconst\\b\\s+)?[a-zA-Z_:][\\w:]*\\s*&?\\s*[a-zA-Z_]\\w*\\s*\\)"
  }
}

resource "zia_dlp_dictionaries" "src_cplusplus_anchor" {
  name                         = "SRC-CPlusPlus Anchor"
  description                  = "C++ structural fingerprint (v4.14): C++ file fingerprint: #include OR using namespace std OR std::-specific types OR stream operators OR template syntax [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*#\\s*include\\s*[<\"]|\\busing\\s+namespace\\s+std\\b|\\bstd::(?:cout|cin|cerr|endl|string|vector|unique_ptr|shared_ptr|make_unique|make_shared|move|forward)\\b|\\b(?:cout|cerr)\\s*<<|\\bcin\\s*>>|\\btemplate\\s*<\\s*(?:typename|class)\\b"
  }
}

resource "zia_dlp_dictionaries" "src_go_signal" {
  name                         = "SRC-Go Signal"
  description                  = "Go syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bpackage\\b\\s+[a-z][a-zA-Z0-9_]*\\s*$"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bimport\\b\\s+(?:\\(|['\"`])"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\btype\\b\\s+[A-Z][A-Za-z0-9_]*\\s+\\b(?:struct|interface)\\b\\s*\\{"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bfunc\\b\\s*\\(\\s*[a-zA-Z_]\\w*\\s+\\*?[A-Z]\\w*\\s*\\)\\s+[a-zA-Z_]\\w*\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bfunc\\b\\s+[a-zA-Z_]\\w*\\s*\\([^)]*\\)"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bfmt\\.(?:Println|Printf|Sprintf|Print|Errorf|Fprintf|Sprintln|Sprint)\\b\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bif\\b\\s+\\berr\\b\\s*!=\\s*\\bnil\\b|\\b(?:errors\\.(?:New|Is|As|Wrap|Unwrap)|fmt\\.Errorf)\\b\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?:\\bgo\\b\\s+\\w+\\s*\\(|\\bdefer\\b\\s+\\w+\\s*\\(|\\bchan\\b\\s+\\*?\\w+)"
  }
}

resource "zia_dlp_dictionaries" "src_go_anchor" {
  name                         = "SRC-Go Anchor"
  description                  = "Go structural fingerprint (v4.14): Go package declaration [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bpackage\\b\\s+[a-z][a-zA-Z0-9_]*\\s*$"
  }
}

resource "zia_dlp_dictionaries" "src_html_signal" {
  name                         = "SRC-HTML Signal"
  description                  = "HTML syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. Tag openings are written \\x3c (the API edge rejects a body contai... [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "<![Dd][Oo][Cc][Tt][Yy][Pp][Ee]\\s+[Hh][Tt][Mm][Ll](?:\\s+[^>]*)?>"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\x3chtml\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\x3chead\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\x3cbody\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\x3ctitle\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\x3cmeta\\s+[^>]*charset\\s*=\\s*['\"]?[A-Za-z0-9-]+['\"]?\\s*/?>"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\x3cscript\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\x3clink\\s+[^>]*rel\\s*=\\s*['\"](?:stylesheet|icon|preload|prefetch)['\"]"
  }
}

resource "zia_dlp_dictionaries" "src_html_anchor" {
  name                         = "SRC-HTML Anchor"
  description                  = "HTML structural fingerprint (v4.14): HTML5 doctype declaration [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "<![Dd][Oo][Cc][Tt][Yy][Pp][Ee]\\s+[Hh][Tt][Mm][Ll](?:\\s+[^>]*)?>"
  }
}

resource "zia_dlp_dictionaries" "src_java_signal" {
  name                         = "SRC-Java Signal"
  description                  = "Java syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bpackage\\b\\s+[a-z][a-zA-Z0-9_]*(?:\\.[a-z][a-zA-Z0-9_]*)*\\s*;"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bimport\\b\\s+(?:\\bstatic\\b\\s+)?(?:java|javax|org|com|io)\\.[a-zA-Z0-9_.*]+\\s*;"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\b(?:public|private|protected|static|final|abstract)\\b\\s+){1,3}\\b(?:class|interface|enum)\\b\\s+[A-Z]\\w*(?:\\s*<[^>]+>)?(?:\\s+\\b(?:extends|implements)\\b\\s+[A-Z]\\w*(?:\\s*,\\s*[A-Z]\\w*)*)*\\s*\\{"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\b(?:public|private|protected)\\b\\s+(?:\\b(?:static|final|abstract|synchronized)\\b\\s+)*(?:\\b(?:void|int|long|double|float|boolean|String)\\b(?:<[^>]+>)?(?:\\[\\])?)\\s+[a-z]\\w*\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*@\\b(?:Override|Deprecated|SuppressWarnings|FunctionalInterface|Test|Before|After|RestController|Service|Component|Autowired|RequestMapping|GetMapping|PostMapping|Entity|Table|Repository|Configuration|Bean)\\b(?:\\s*\\([^)]*\\))?"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bSystem\\.(?:out|err)\\.(?:println|print|printf)\\b\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bnew\\s+(?:ArrayList|HashMap|HashSet|LinkedList|TreeMap|TreeSet|Vector|Stack|PriorityQueue|LinkedHashMap|LinkedHashSet|ConcurrentHashMap|CopyOnWriteArrayList)\\s*<"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?:\\bthrow\\b\\s+\\bnew\\b\\s+(?:[A-Z]\\w*)?Exception\\b\\s*\\(|\\bcatch\\b\\s*\\(\\s*[A-Z]\\w*Exception\\b)"
  }
}

resource "zia_dlp_dictionaries" "src_java_anchor" {
  name                         = "SRC-Java Anchor"
  description                  = "Java structural fingerprint (v4.14): Java main method OR import from Java-distinctive package roots [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)\\bpublic\\s+static\\s+void\\s+main\\s*\\(|^\\s*\\bimport\\b\\s+(?:static\\s+)?[a-z][\\w.]*\\s*;"
  }
}

resource "zia_dlp_dictionaries" "src_javascript_signal" {
  name                         = "SRC-JavaScript Signal"
  description                  = "JavaScript syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\brequire\\b\\s*\\(\\s*['\"]"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bmodule\\.exports\\b|\\bexports\\.[a-zA-Z_$]|\\brequire\\b\\s*\\(\\s*['\"]"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bmodule\\.exports\\b\\s*="
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bfunction\\b(?:\\s+[a-zA-Z_$][a-zA-Z0-9_$]*)?\\s*\\([^)]*\\)\\s*\\{"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?:[=(,]|\\breturn\\b|\\bawait\\b)\\s*(?:\\([^)]*\\)|\\b[a-zA-Z_$][\\w$]+)\\s*=>\\s*[\\{a-zA-Z_$\\(]"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:const|let|var)\\b\\s+\\{"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bconsole\\.(?:log|error|warn|info|debug|trace)\\b\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?:\\bfetch\\b\\s*\\(|\\.then\\b\\s*\\(|\\bPromise\\.(?:all|race|resolve|reject|allSettled)\\b|\\bnew\\s+Promise\\s*\\(|\\bawait\\s+\\w+\\.\\w+\\s*\\()"
  }
}

resource "zia_dlp_dictionaries" "src_javascript_anchor" {
  name                         = "SRC-JavaScript Anchor"
  description                  = "JavaScript structural fingerprint (v4.14): CommonJS module syntax: module.exports OR require() [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bmodule\\.exports\\b|\\brequire\\b\\s*\\(\\s*['\"]"
  }
}

resource "zia_dlp_dictionaries" "src_kotlin_signal" {
  name                         = "SRC-Kotlin Signal"
  description                  = "Kotlin syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bpackage\\b\\s+[a-z][a-zA-Z0-9_]*(?:\\.[a-z][a-zA-Z0-9_]*)*\\s*$"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bimport\\b\\s+(?:kotlin(?:x)?\\.[a-z]|[a-z][a-zA-Z0-9_.]*\\.\\*\\s*$)"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\b(?:public|private|protected|internal|open|final|abstract|sealed)\\b\\s+){0,2}\\b(?:data|sealed)\\b\\s+\\bclass\\b\\s+[A-Z][A-Za-z0-9_]*"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\b(?:public|private|protected|internal|override|open|final|abstract|inline|suspend)\\b\\s+){0,3}\\bfun\\b\\s+(?:<[^>]+>\\s+)?[a-zA-Z_]\\w*\\s*\\([^)]*\\)"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:suspend\\b\\s+\\bfun\\b|launch\\s*[\\{\\(]|async\\s*[\\{\\(]|runBlocking\\s*[\\{\\(]|withContext\\s*\\(|coroutineScope\\s*\\{)"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)\\bwhen\\b\\s*(?:\\([^)]+\\))?\\s*\\{|^\\s*\\b(?:val|var)\\b\\s+[a-zA-Z_]\\w*\\s*(?::\\s*[A-Z]\\w*[\\w<>?\\[\\],\\s]{0,100})?\\s*="
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bfun\\b\\s+[A-Z][A-Za-z0-9_<>?]*\\.[a-zA-Z_]\\w*\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\bcompanion\\b\\s+)?\\bobject\\b(?:\\s+[A-Z][A-Za-z0-9_]*)?\\s*[\\{:]|\\bcompanion\\s+object\\b"
  }
}

resource "zia_dlp_dictionaries" "src_kotlin_anchor" {
  name                         = "SRC-Kotlin Anchor"
  description                  = "Kotlin structural fingerprint (v4.14): Kotlin function (`fun`) or data class declaration [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bfun\\b\\s+[a-zA-Z_]\\w*\\s*[(<]|\\bdata\\s+class\\b"
  }
}

resource "zia_dlp_dictionaries" "src_python_signal" {
  name                         = "SRC-Python Signal"
  description                  = "Python syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bfrom\\b\\s+[a-zA-Z_][a-zA-Z0-9_.]*\\s+\\bimport\\b\\s+(?:[a-zA-Z_*][a-zA-Z0-9_,\\s]*|\\([^)]+\\))"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bimport\\b\\s+(?:\\w+\\s+\\bas\\s+\\w|(?:os|sys|json|re|math|asyncio|collections|itertools|functools|typing|logging|pathlib|argparse|hashlib|random|time|numpy|pandas|requests|flask|django|fastapi|sqlalchemy|pydantic|httpx)\\b)"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\basync\\b\\s+)?\\bdef\\b\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*\\([^)]*\\)\\s*:"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bclass\\b\\s+[A-Z][a-zA-Z0-9_]*(?:\\([^)]*\\))?\\s*:\\s*(?:#.*)?$"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bif\\b\\s+\\b__name__\\b\\s*==\\s*['\"]__main__['\"]\\s*:"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b__init__\\b\\s*\\(\\s*\\bself\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bfor\\b\\s+[a-zA-Z_][a-zA-Z0-9_]*(?:\\s*,\\s*[a-zA-Z_][a-zA-Z0-9_]*)*\\s+\\bin\\b\\s+\\S.*:"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bwith\\b\\s+\\S.*\\s+\\bas\\b\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*:"
  }
}

resource "zia_dlp_dictionaries" "src_python_anchor" {
  name                         = "SRC-Python Anchor"
  description                  = "Python structural fingerprint (v4.14): Python function definition OR main guard OR from-import [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bdef\\b\\s+[a-zA-Z_]\\w*\\s*\\([^)]*\\)\\s*:|^\\s*\\bif\\b\\s+\\b__name__\\b\\s*==|^\\s*\\bfrom\\b\\s+[a-zA-Z_][\\w.]*\\s+\\bimport\\b"
  }
}

resource "zia_dlp_dictionaries" "src_rust_signal" {
  name                         = "SRC-Rust Signal"
  description                  = "Rust syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\buse\\b\\s+[a-zA-Z_][a-zA-Z0-9_:]*(?:::\\{[^}]+\\})?(?:::\\*)?\\s*;"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\bpub\\b(?:\\([^)]+\\))?\\s+)?\\bstruct\\b\\s+[A-Z][A-Za-z0-9_]*(?:<[^>]+>)?"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bimpl\\b(?:<[^>]+>)?\\s+(?:[A-Z][A-Za-z0-9_]*(?:<[^>]+>)?\\s+\\bfor\\b\\s+)?[A-Z][A-Za-z0-9_]*"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\bpub\\b\\s+)?\\btrait\\b\\s+[A-Z][A-Za-z0-9_]*(?:<[^>]+>)?"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\bpub\\b\\s+)?\\benum\\b\\s+[A-Z][A-Za-z0-9_]*(?:<[^>]+>)?\\s*\\{"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\bpub\\b(?:\\([^)]+\\))?\\s+)?(?:\\basync\\b\\s+)?\\bfn\\b\\s+[a-zA-Z_]\\w*\\s*(?:<[^>]+>)?\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bmatch\\b\\s+[\\w.\\[\\](){}&*]+\\s*\\{"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:Result|Option)\\s*<"
  }
}

resource "zia_dlp_dictionaries" "src_rust_anchor" {
  name                         = "SRC-Rust Anchor"
  description                  = "Rust structural fingerprint (v4.14): Rust function declaration OR impl block OR use statement [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\bpub\\b\\s+)?\\bfn\\b\\s+[a-zA-Z_]\\w*\\s*[(<]|^\\s*\\bimpl\\b\\s+(?:<[^>]+>\\s+)?[A-Z]|^\\s*\\buse\\b\\s+[a-zA-Z_][\\w:]*(?:::\\{[^}]+\\})?(?:::\\*)?\\s*;"
  }
}

resource "zia_dlp_dictionaries" "src_sql_signal" {
  name                         = "SRC-SQL Signal"
  description                  = "SQL syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[Ss][Ee][Ll][Ee][Cc][Tt]\\b\\s+(?:\\*|\\bDISTINCT\\b|\\bTOP\\b|[A-Za-z_\"`\\[])"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[Ii][Nn][Ss][Ee][Rr][Tt]\\b\\s+\\b[Ii][Nn][Tt][Oo]\\b\\s+[\\w.\\[\\]\"`]+\\s*(?:\\([^)]+\\))?\\s+\\b[Vv][Aa][Ll][Uu][Ee][Ss]\\b\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[Uu][Pp][Dd][Aa][Tt][Ee]\\b\\s+[\\w.\\[\\]\"`]+\\s+\\b[Ss][Ee][Tt]\\b\\s+\\w+\\s*="
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[Dd][Ee][Ll][Ee][Tt][Ee]\\b\\s+\\b[Ff][Rr][Oo][Mm]\\b\\s+[\\w.\\[\\]\"`]+"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:CREATE|create)\\s+(?:OR\\s+REPLACE\\s+|or\\s+replace\\s+)?(?:TABLE|table|DATABASE|database|SCHEMA|schema|INDEX|index|VIEW|view|PROCEDURE|procedure|FUNCTION|function|TRIGGER|trigger)\\s+(?:IF\\s+NOT\\s+EXISTS\\s+|if\\s+not\\s+exists\\s+)?[\\w.\\[\\]\"`]+"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:[Aa][Ll][Tt][Ee][Rr]|[Dd][Rr][Oo][Pp])\\b\\s+\\b(?:[Tt][Aa][Bb][Ll][Ee]|[Dd][Aa][Tt][Aa][Bb][Aa][Ss][Ee]|[Ii][Nn][Dd][Ee][Xx]|[Vv][Ii][Ee][Ww]|[Ss][Cc][Hh][Ee][Mm][Aa])\\b\\s+(?:\\b[Ii][Ff]\\b\\s+\\b[Ee][Xx][Ii][Ss][Tt][Ss]\\b\\s+)?[\\w.\\[\\]\"`]+"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:[Ii][Nn][Nn][Ee][Rr]|[Ll][Ee][Ff][Tt]|[Rr][Ii][Gg][Hh][Tt]|[Ff][Uu][Ll][Ll]|[Cc][Rr][Oo][Ss][Ss])?\\b\\s*(?:\\b[Oo][Uu][Tt][Ee][Rr]\\b)?\\s*\\b[Jj][Oo][Ii][Nn]\\b\\s+[\\w.\\[\\]\"`]+\\s+(?:[a-zA-Z]+\\s+)?\\b[Oo][Nn]\\b\\s+"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:[Gg][Rr][Oo][Uu][Pp]|[Oo][Rr][Dd][Ee][Rr])\\b\\s+\\b[Bb][Yy]\\b\\s+[\\w.,\\s]{1,200}"
  }
}

resource "zia_dlp_dictionaries" "src_sql_anchor" {
  name                         = "SRC-SQL Anchor"
  description                  = "SQL structural fingerprint (v4.14): Line-anchored SQL DDL or DML at start of line [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:CREATE(?:\\s+OR\\s+REPLACE)?\\s+(?:TABLE|INDEX|VIEW|SCHEMA|FUNCTION|PROCEDURE|TRIGGER)|(?:ALTER|DROP)\\s+(?:TABLE|INDEX|VIEW|SCHEMA)|INSERT\\s+INTO|DELETE\\s+FROM|UPDATE\\s+\\w+\\s+SET|SELECT\\s+(?:\\*|\\w)|WITH\\s+\\w+\\s+AS|GRANT\\s+|SET\\s+\\w+\\s*=)"
  }
}

resource "zia_dlp_dictionaries" "src_swift_signal" {
  name                         = "SRC-Swift Signal"
  description                  = "Swift syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\bimport\\b\\s+\\b(?:Foundation|UIKit|SwiftUI|Combine|CoreData|AVFoundation|MapKit|XCTest|CryptoKit|StoreKit|WidgetKit|AppKit|Dispatch)\\b\\s*$"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:protocol|extension|actor)\\s+[A-Z]\\w*|\\bfinal\\s+class\\s+[A-Z]\\w*|\\b(?:struct|enum|class)\\s+[A-Z]\\w*\\s*:\\s*(?:Codable|Identifiable|Hashable|Equatable|ObservableObject|View|Sendable|CaseIterable|RawRepresentable|Error|LocalizedError)"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bfunc\\b\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*(?:<[^>]+>)?\\s*\\([^)]*\\)\\s*(?:\\basync\\b\\s+)?(?:\\bthrows\\b\\s+)?(?:->\\s*[A-Za-z_\\[\\]\\?\\!,\\s<>]+\\s*)?\\{"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bguard\\b\\s+\\blet\\b\\s+[a-zA-Z_]\\w*\\s*="
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bif\\b\\s+\\blet\\b\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*=\\s*"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\binit\\b\\s*[?!]?\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\b(?:let|var)\\b\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*:\\s*[A-Z][A-Za-z0-9_<>\\[\\]?!,\\s]*"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\\\\\([a-zA-Z_$]"
  }
}

resource "zia_dlp_dictionaries" "src_swift_anchor" {
  name                         = "SRC-Swift Anchor"
  description                  = "Swift structural fingerprint (v4.14): Swift-distinctive constructs: guard let, func with throws/->, or Apple framework import [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)\\bguard\\b\\s+\\blet\\b\\s+[a-zA-Z_]\\w*\\s*=|\\bfunc\\b\\s+[a-zA-Z_]\\w*\\s*\\([^)]*\\)\\s*(?:async\\s+)?(?:throws|->)|^\\s*\\bimport\\b\\s+\\b(?:Foundation|UIKit|SwiftUI|Combine|XCTest|CoreData|AVFoundation|MapKit|CryptoKit|StoreKit|WidgetKit|AppKit|Dispatch)\\b"
  }
}

resource "zia_dlp_dictionaries" "src_typescript_signal" {
  name                         = "SRC-TypeScript Signal"
  description                  = "TypeScript syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bimport\\b\\s+(?:\\{|\\*\\s+\\bas\\b|[a-zA-Z_$])(?:[\\w$,\\s\\{\\}\\*]*?)\\s+\\bfrom\\b\\s+['\"]"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\bexport\\b\\s+)?\\binterface\\b\\s+[A-Z][A-Za-z0-9_]*(?:<[^>]+>)?(?:\\s+\\bextends\\b\\s+[A-Z][A-Za-z0-9_,\\s<>]+)?\\s*\\{"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\bexport\\b\\s+)?\\btype\\b\\s+[A-Z][A-Za-z0-9_]*(?:<[^>]+>)?\\s*="
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\bexport\\b\\s+)?(?:\\babstract\\b\\s+)?\\bclass\\b\\s+[A-Z][A-Za-z0-9_]*(?:<[^>]+>)?(?:\\s+\\b(?:extends|implements)\\b\\s+[A-Z][A-Za-z0-9_,\\s<>]+)?\\s*\\{"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = ":\\s*\\b(?:string|number|boolean|void|null|undefined|any|unknown|never|Promise|Array|Record|Partial|Readonly|Map|Set)\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\bexport\\b\\s+)?\\benum\\b\\s+[A-Z][A-Za-z0-9_]*\\s*\\{"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\basync\\b\\s+(?:\\bfunction\\b|[a-zA-Z_$][a-zA-Z0-9_$]*\\s*\\()"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\bPromise\\s*<"
  }
}

resource "zia_dlp_dictionaries" "src_typescript_anchor" {
  name                         = "SRC-TypeScript Anchor"
  description                  = "TypeScript structural fingerprint (v4.14): TypeScript-distinctive: type alias OR import type OR TS utility type [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:\\bexport\\b\\s+)?\\btype\\b\\s+[A-Z]\\w*(?:<[^>]+>)?\\s*=|\\bimport\\s+type\\b|\\b(?:Record|Readonly|Partial|Required|Pick|Omit|NonNullable|ReturnType|Awaited|Parameters)\\s*<"
  }
}

resource "zia_dlp_dictionaries" "src_vbnet_signal" {
  name                         = "SRC-VBNet Signal"
  description                  = "Visual Basic (.NET) syntax evidence (v4.14): 8 patterns counted as unique matches. Fires the engine only together with the Anchor. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\b[Ii][Mm][Pp][Oo][Rr][Tt][Ss]\\b\\s+[A-Z][A-Za-z0-9]+(?:\\.[A-Z][A-Za-z0-9]+)*\\s*$"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\b(?:[Nn][Aa][Mm][Ee][Ss][Pp][Aa][Cc][Ee]|[Mm][Oo][Dd][Uu][Ll][Ee])\\b\\s+[A-Z][A-Za-z0-9_]*\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:Public|Private|Friend|Protected)(?:\\s+(?:Shared|Overrides|MustInherit|NotInheritable|Partial|MustOverride|Overridable))?\\s+Class\\s+[A-Z]\\w*"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*(?:[A-Za-z]{4,}\\s+){0,3}\\b(?:[Ss][Uu][Bb]|[Ff][Uu][Nn][Cc][Tt][Ii][Oo][Nn])\\b\\s+[A-Z][A-Za-z0-9_]*\\b\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[Ee][Nn][Dd]\\b\\s+\\b(?:[Ss][Uu][Bb]|[Ff][Uu][Nn][Cc][Tt][Ii][Oo][Nn]|[Cc][Ll][Aa][Ss][Ss]|[Mm][Oo][Dd][Uu][Ll][Ee]|[Nn][Aa][Mm][Ee][Ss][Pp][Aa][Cc][Ee]|[Ii][Nn][Tt][Ee][Rr][Ff][Aa][Cc][Ee]|[Ee][Nn][Uu][Mm]|[Ss][Tt][Rr][Uu][Cc][Tt][Uu][Rr][Ee])\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[Dd][Ii][Mm]\\b\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s+\\b[Aa][Ss]\\b\\s+(?:\\b[Nn][Ee][Ww]\\b\\s+)?[A-Z][A-Za-z0-9_]*\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[Cc][Oo][Nn][Ss][Oo][Ll][Ee]\\.(?:[Ww][Rr][Ii][Tt][Ee][Ll][Ii][Nn][Ee]|[Ww][Rr][Ii][Tt][Ee]|[Rr][Ee][Aa][Dd][Ll][Ii][Nn][Ee]|[Rr][Ee][Aa][Dd][Kk][Ee][Yy])\\b\\s*\\("
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[Ff][Oo][Rr]\\b\\s+(?:\\b[Ee][Aa][Cc][Hh]\\b\\s+)?[a-zA-Z_][a-zA-Z0-9_]*\\s+\\b[Aa][Ss]\\b\\s+[A-Z]\\w*\\b"
  }
}

resource "zia_dlp_dictionaries" "src_vbnet_anchor" {
  name                         = "SRC-VBNet Anchor"
  description                  = "Visual Basic (.NET) structural fingerprint (v4.14): VB structural markers: Imports + capital identifier OR End Sub/Function/etc. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?m)^\\s*\\b[Ii][Mm][Pp][Oo][Rr][Tt][Ss]\\b\\s+[A-Z]|\\b[Ee][Nn][Dd]\\s+(?:[Ss][Uu][Bb]|[Ff][Uu][Nn][Cc][Tt][Ii][Oo][Nn]|[Cc][Ll][Aa][Ss][Ss]|[Mm][Oo][Dd][Uu][Ll][Ee]|[Nn][Aa][Mm][Ee][Ss][Pp][Aa][Cc][Ee]|[Ss][Tt][Rr][Uu][Cc][Tt][Uu][Rr][Ee])\\b"
  }
}

resource "zia_dlp_dictionaries" "src_encrypted_or_ascii_armored_pgp_keys" {
  name                         = "SRC-Encrypted or ASCII Armored PGP Keys"
  description                  = "From the Fed pack (Encrypted or ASCII Armored PGP Keys). [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "-{4,5}BEGIN (PGP|ENCRYPTED) PRIVATE\\b"
  }
}

resource "zia_dlp_dictionaries" "src_encrypted_bouncy_castle_key_exports" {
  name                         = "SRC-Encrypted Bouncy Castle Key Exports"
  description                  = "Bouncy Castle Key Exports triggers against the unique phrase within the exported key indicating it is encrypted [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 500
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "\\bProc-Type: 4,ENCRYPTED\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Private Key"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "DEK-Info"
  }
}

resource "zia_dlp_dictionaries" "src_private_keys_plaintext_regex" {
  name                         = "SRC-Private Keys-Plaintext Regex"
  description                  = "Detect Elliptic Curve(EC), Digital Signature Algorithm (DSA), Rivest-Shamir-Adleman (RSA), Secure Shell 2(SSH2), OpenSSH, Pretty Good Privacy(PGP), Gnu Privacy Guard(GPG) Private ke... [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_ALL"
    pattern = "[- ]{4,5}BEGIN (EC|DSA|RSA|SSH2|OPENSSH|PGP|GPG) PRIVA"
  }
}

resource "zia_dlp_dictionaries" "src_jwk_private_key" {
  name                         = "SRC-JWK Private Key"
  description                  = "From the Fed pack (JWK Private Key). [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 500
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\"kty\" ?: ?\"(EC|RSA)\""
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "'\"d\"'"
  }
}

resource "zia_dlp_dictionaries" "src_private_key" {
  name                         = "SRC-Private Key"
  description                  = "Detect leakage of credentials and secrets [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.cred_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_MEDIUM"
  include_bin_numbers          = true
  # include_ssn_numbers = true  (not supported by the zscaler/zia provider; set in the portal)
  hierarchical_identifiers     = ["CRED_PRIVATE_KEY"]
}

