from PyNakasendo import PyNakasendo

def main() -> None:
    print('Starting BigNum')
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

def main_ec() -> None:
    print("starting ECPoint")
    #039381238A139463E2AC961E4B76E8F063E79353D4AADB3F0EA80A48A023998C00,-024C746B98B3834298104EB5582A966E8715673C5AB24CCA20457B12E95959ECF5,031409D41454F2024E32493EC3612E053A18282665B2F7D1FF459FF369C302A479
    ec_pt_a = PyNakasendo.PyECPoint(714)
    ec_pt_a.FromHex("039381238A139463E2AC961E4B76E8F063E79353D4AADB3F0EA80A48A023998C00")
    ec_pt_b = PyNakasendo.PyECPoint(714)
    ec_pt_b.FromHex("-024C746B98B3834298104EB5582A966E8715673C5AB24CCA20457B12E95959ECF5")
    ec_pt_res_file = PyNakasendo.PyECPoint(714)
    ec_pt_res_file.FromHex("031409D41454F2024E32493EC3612E053A18282665B2F7D1FF459FF369C302A479")

    print(f'pt_a -> {ec_pt_a.ToHex()} + pt_b -> {ec_pt_b.ToHex()}')


    ec_pt_no_param = PyNakasendo.PyECPoint()
    ec_pt_no_param.SetRandom()
    print(f'Random EC point defaulted to secp256k1-> {ec_pt_no_param}')
    
if __name__ == "__main__":
    main()
    main_ec()
    print('Ending')