def djb2(key: str):
    # Implementation of Daniel J. Bernstein's djb2-hash
    # (https://theartincode.stanis.me/008-djb2/)

    hsh = 5381
    for char in key:
        print(char)
        hsh = ((hsh << 5) + hsh) + ord(char)
    return hsh


print(djb2("tim") % 256)
print(djb2("archlinux2") % 256)
