
def analyze_text_file(path, input_file):
    """
    Input: txt file content
    Output: List of password found and line number
    Output1: List of user found and line number
    """
    if not input_file.endswith('.txt'):
        return
    f = open("/home/guillaume/Documents/Devleppement/Git-repo/Django-PhishInspector/result/6924217-accs.txt",'r')
    content = f.readlines()
    line_number = 0
    password_dict = {}
    user_dict = {}
    for line in content:
        line_number = line_number + 1
        if "password" in line.lower():
            password_dict[line_number] = line
        elif "user" in line.lower():
            user_dict[line_number] = line
    return password_dict, user_dict


out = analyze_text_file("/home/guillaume/Documents/Devleppement/Git-repo/Django-PhishInspector/result/","6924217-accs.txt")
print(out)
