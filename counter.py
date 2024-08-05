import os

total = 0

for k in os.scandir('.'):
    if k.name.endswith('.py'):
        with open(k.name, 'rb') as f:
            content = f.read()
            for r in content:
                if r == 10:
                    total += 1
print(total)
