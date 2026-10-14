counted = []

with open("output/cherokee.com.br_20260806_105018/recon/dns/live-ips.txt", "r+") as file:
    lines = file.readlines()
    for line in lines:
        if line.strip() not in counted:
            counted.append(line.strip())
        else:
            continue

for line in counted:
    print(line.strip())
