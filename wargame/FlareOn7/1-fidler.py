# Keyword : Python Reversing

def decode_flag(frob):
    last_value = frob
    encoded_flag = [1135, 1038, 1126, 1028, 1117, 1071, 1094, 1077, 1121, 1087, 1110, 1092, 1072, 1095, 1090, 1027,
                    1127, 1040, 1137, 1030, 1127, 1099, 1062, 1101, 1123, 1027, 1136, 1054]
    decoded_flag = []

    for i in range(len(encoded_flag)):
        c = encoded_flag[i]
        val = (c - ((i%2)*1 + (i%3)*2)) ^ last_value
        decoded_flag.append(val)
        last_value = c

    return ''.join([chr(x) for x in decoded_flag])

# password_screen
altered_key = 'hiptu'
key = ''.join([chr(ord(x) - 1) for x in altered_key])
print(key)

# game_screen
print(decode_flag(((2**36) + (2**35) + 2**20) // 10**8)) # 1030

# flag : idle_with_kitty@flare-on.com