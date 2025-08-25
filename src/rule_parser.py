# src/rule_parser.py
import re

class RuleParser:
    def __init__(self, rules_file):
        self.rules_file = rules_file

    def parse(self):
        parsed_rules = []
        with open(self.rules_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                rule = self._parse_line(line)
                if rule:
                    parsed_rules.append(rule)
                else:
                    print(f"[AVISO] Ignorando regra malformada na linha {line_num}: {line}")
        return parsed_rules

    def _parse_line(self, line):
        rule_regex = re.compile(
            r'^(?P<action>\w+)\s+'
            r'(?P<proto>\w+)\s+'
            r'(?P<src_ip>[\w\.]+)\s+'
            r'(?P<src_port>[\w\.]+)\s+'
            r'->\s+'
            r'(?P<dst_ip>[\w\.]+)\s+'
            r'(?P<dst_port>[\w\.]+)\s+'
            r'\((?P<options>.*)\)$'
        )
        
        match = rule_regex.match(line)
        if not match:
            return None

        rule_dict = match.groupdict()
        rule_dict['options'] = self._parse_options(rule_dict['options'])
        return rule_dict

    def _parse_options(self, options_str):
        options = {}
        option_regex = re.compile(r'(\w+):"([^"]+)";|(\w+):([\w_]+);')
        
        for match in option_regex.finditer(options_str):
            if match.group(1):
                key, value = match.group(1), match.group(2)
            else:
                key, value = match.group(3), match.group(4)
            options[key] = value
        return options