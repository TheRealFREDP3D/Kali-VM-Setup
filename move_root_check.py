with open('install.sh', 'r') as f:
    lines = f.readlines()

root_check_lines = lines[117:121]
# Remove them
del lines[117:121]

# Insert after log "Starting CTF VM setup" which is around 113
for i, line in enumerate(lines):
    if 'log "Starting CTF VM setup"' in line:
        lines[i+1:i+1] = root_check_lines
        break

with open('install.sh', 'w') as f:
    f.writelines(lines)
