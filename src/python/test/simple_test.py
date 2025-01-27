from PyNakasendo import PyNakasendo

def main() -> None:
    print('Starting')
    val = PyNakasendo.PyBigNumber()
    val.One()
    print(val)
    val.GenerateRandHex(512)
    print(val)

    val1 = PyNakasendo.PyBigNumber()
    val1.GenerateRandHex(512)
    val2 = PyNakasendo.PyBigNumber()
    val2.GenerateRandHex(512)

    val3 = val1 + val2

    print(f'val1 -> {val1}\nval2 -> {val2}')
    print(f'{type(val3)}')
    print(val3)
    val.One()
    val4 = val + 1
    print(val4)

if __name__ == "__main__":
    main()
    print('Ending')