import sys

if __name__ == "__main__":
    for fn in sys.argv:
        with open(fn, "r") as f:
            ls = f.read().splitlines()
        length = filter(lambda l: l.startswith("Len = "), ls)
        msg = filter(lambda l: l.startswith("Msg = "), ls)
        md = filter(lambda l: l.startswith("MD = "), ls)
        for (l, m, d) in zip(length, msg, md):
            l = 2*int(l.split()[2])
            print("TestVector {")
            print(f"    msg: \"{m.split()[2][:l]}\",")
            print(f"    digest: \"{d.split()[2]}\",")
            print("},")
