#include <iostream>
#include <regex>

bool is_malicious_input(const std::string& input) {
    static const std::regex pattern(
        R"((\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|--|;|SHUTDOWN|EXEC|XP_CMD|SYSTEM)\b|['"\\]))",
        std::regex_constants::icase
    );
    return std::regex_search(input, pattern);
}

bool is_xss_input(const std::string& input) {
    static const std::regex xss_pattern(
        R"((<script.*?>.*?</script>|<.*?on\w+\s*=|javascript:|document\.|window\.|eval\())",
        std::regex_constants::icase
    );
    return std::regex_search(input, xss_pattern);
}

int main() {
  bool a = is_malicious_input("example");
  bool b = is_xss_input("<script>alert(0)</script>");
  return 0;
}
