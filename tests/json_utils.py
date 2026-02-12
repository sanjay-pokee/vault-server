
import json
import re

def load_json_with_comments(file_path):
    """
    Loads a JSON file that may contain C-style comments (//).
    Strips comments before parsing.
    """
    with open(file_path, "r") as f:
        content = f.read()
        
    # Remove // comments 
    # This regex matches // until end of line
    # It doesn't handle // inside strings, but for our simple data it's fine.
    # A more robust regex: re.sub(r'(?m)^ *//.*\n?', '', content)
    
    # Simple line-based filtering is safer for now to avoid regex complexity issues
    lines = content.splitlines()
    filtered_lines = []
    for line in lines:
        if "//" in line:
            # Check if // is inside a string? 
            # For our use case (comments at end of line or on own line), simple split is okay.
            # strict split at // might break "http://..."
            # So we only strip if it's likely a comment.
            # But wait, https_config.json has URLs! "https://..."
            # We must NOT strip "https://"
            
            # Strategy: Only strip if // is preceded by whitespace or is start of line,
            # AND not part of a URL pattern like ": //"
            
            # Better strategy: rely on the user's "comment" usage.
            # They will likely put it on a separate line or at end of line.
            # Let's perform a careful strip.
            
            # If line contains "https://" or "http://", we might need to be careful.
            # But the user wants comments.
            
            parts = line.split("//")
            
            # Reconstruct valid parts. 
            # If the first part ends with ": " or "http:" or "https:", it's likely a URL.
            pre_comment = parts[0]
            if "http:" in pre_comment or "https:" in pre_comment:
                # Likely a URL, keep the line as is (assuming no comment on same line as URL)
                filtered_lines.append(line)
            else:
                # Take only the part before //
                if pre_comment.strip():
                    filtered_lines.append(pre_comment)
        else:
            filtered_lines.append(line)
            
    clean_json = "\n".join(filtered_lines)
    return json.loads(clean_json)
