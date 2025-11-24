from gmpy2 import isqrt, is_square, f_divmod
from tqdm import tqdm  
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long  
from sys import setrecursionlimit  

setrecursionlimit(10000)  # Increase recursion limit for potential deep calls for function (rational_to_contfrac,contfrac_to_rational)
fdivmod = f_divmod  # Alias for easier use

def trivial_factorization_with_n_phi(N, phi):
    """
    Factorizes N given its value and its Euler's totient phi.
    This is a simple factorization method applicable when phi is known.
    """
    m = N - phi + 1
    m2N2 = pow(m, 2) - 4 * N
    if m2N2 > 0:
        i = isqrt(m2N2)  # Integer square root
        roots = int((m - i) >> 1), int((m + i) >> 1)  # Calculate potential roots
        if roots[0] * roots[1] == N:  # Check if they are indeed factors
            return roots  # Return the factors

def rational_to_contfrac(x, y):
    """
    Converts a rational number x/y to a list of continued fraction terms.
    This is used in the Wiener attack to approximate fractions related to the private exponent.
    """
    a = x // y  # Integer quotient
    if a * y == x:
        return [a]  # Base case for exact division
    else:
        pquotients = rational_to_contfrac(y, x - a * y)  # Recursively compute remaining terms
        pquotients.insert(0, a)  # Add the current quotient to the beginning
        return pquotients

def convergents_from_contfrac(frac, progress=False):
    """
    Generates a list of convergents (rational approximations) from a continued fraction representation.
    These convergents are used to try and find a suitable fraction that reveals the private exponent.
    """
    convs = []
    for i in range(0, len(frac)):
        convs.append(contfrac_to_rational(frac[0:i]))  # Compute convergents up to the i-th term
    return convs

def contfrac_to_rational(frac):
    """
    Converts a list of continued fraction terms back to a rational number (numerator, denominator) pair.
    This is used to generate the convergents.
    """
    if len(frac) == 0:
        return (0, 1)  # Base case for empty fraction
    elif len(frac) == 1:
        return (frac[0], 1)  # Base case for single-term fraction
    else:
        remainder = frac[1:len(frac)]
        (num, denom) = contfrac_to_rational(remainder)  # Recursively compute the rest
        return (frac[0] * num + denom, num)  # Apply continued fraction formula

def wiener_attack(n, e, progress=True):
    """
    Implements the Wiener attack on RSA, attempting to factor the modulus n given the public exponent e.
    The attack exploits a vulnerability when the private exponent d is small compared to the modulus.
    """
    convergents = convergents_from_contfrac(rational_to_contfrac(e, n))  # Generate convergents

    for (k, d) in tqdm(convergents, f'Try Find Factors', unit='B', unit_scale=True, unit_divisor=1024, disable=(not progress)):
        # Iterate through convergents to find a suitable fraction
        if k != 0:
            phi, q = fdivmod((e * d) - 1, k)  # Check if the fraction leads to a possible phi value
            if (phi & 1 == 0) and (q == 0):  # Ensure phi is even and the division is exact
                s = n - phi + 1  # Calculate a potential value for S (related to pq)
                discr = s**2-4*n  # Calculate the discriminant for potential factorization
                t = 0  # Initialize variable for potential T
                if (discr > 0 and is_square(discr)):  # Check if the discriminant is positive and a square
                    t = isqrt(discr)  # Take the square root if possible
                if (s + t) & 1 == 0:  # Check if the sum of S and T is even
                    pq = trivial_factorization_with_n_phi(n, phi)  # Attempt factorization using S and the potential phi
                    if pq is not None:  # Success if factors are found
                        return pq  # Return the factors
    return None,None

def prRed(skk): print("\033[91m{}\033[00m" .format(skk))
def prGreen(skk): print("\033[92m{}\033[00m" .format(skk))
def prCyan(skk): print("\033[96m{}\033[00m" .format(skk))
def main():
 public_server_n=3334856810184677477844358144018917794041731190055839506761047725196006094980863695382177363193369966486016701249215142483636637554021814543035830546215989929795663440797135714052529156584121356430820344157690550828800881814240591307966102200317439798025514933024378636034699031813537269957366107757164860989844073107586429425720904855051982116041375607063348284181020075517929415641544289763746613008111428479297057733166557625147336147566880214355650641577166264521190299115885380737405565001610566944363859489100969586274685083957891857940299867778179224315829434940724792203814646820239647654928926010057013368458245514278044491268911004184046810260941759997123197041098733517706050844547145597277455472453774614055218254132399751743258899881787475545751497375960922131268299479552529031035888108780949909103896592757431124458704783417755010801978390551651313047542712508524793275560368174745062513752629553237925010211952156417038790055587317248535295143994247940211251656493513423704508343198542105407781884990875230425908547394673929549851133924331163825482577078961944622191862486639441372854700487426887512910454786510827672456213611323195410584868699053780747730586864834422625763265388125692936999503906754918551854172173689
 public_server_e=2886742484284236738106774553791894046416444145459517541766656102330583532154902136604981835389880876713510845417271964019204206949327057151814809422028064218677671539780756790073245011971779691151399771785594074102959490942011855461922052373256869112586069827237757677531152193793922244290357631084923476294942724769982806739137984440930721076461131445531563983299231761780264950983814074640237982898488917656165224244195387250924608815967348988209556714420639312419361130926877862538413221196848322559474276711620086565581403677553882228263027399722889281656046918967381048807623526364266143600256088104112918099637085367138980880401801929864949191436201487350316442963262388421086044955615708039631976078142986495395413372609466947411695520320289903706466828341807884432581092036782685314853874294858647103670051043525755503755113156275596704174274371810869392692475528911042436194087115337615374222449956292870848959480797114952026583740853480852705976157805343363101525183964560440988129944984991815645605643759337280581457184559678726060653232062032958445566260119329244132071683732161836203152982640205805727156468285180704488652033448482014914282137473931519173301689100603078652134608031181394091081450726382793079353630028427 
 msg_captured_hex=["132440f7e6b97f6fd1b4c4eb4441cd170ab387dca33954956e679fd533c9eb98e39a421791c34ca38ae276ae403312228a0728fdce680f902a28258d1d9fd79c9221bc67af6fbc56d350e48d788416121ab924aa280080afc3e1da8d5d89a446720f32ee293b00c7be75f5602f8dbf87c7e27c8acea5e6e8b30b89b0cabfff2bab86b4c1973c623da1a60c00e477772ea5d4536b5a84f0b3af20a8912ac5bead7c724b1be6d6ffe6640364740439bf6eb66e1d98d8a5cddce618c1b7385fd9aa6939a60a61156f8ed0c79ba4117e7a2c8f13f4a07d3834a088cdb88cc67ecd32fa18e875de3facba650f2452f3f7406ba6ddd0e60a3a6e2c8297f3862c7ad209888672f9ae04b8d9aab7546cf41fe62ea3af2f9bc96fc9fb3a4a4eb1dfafde1560a0036b6896d77d6a02a296630f2d7de5dca87224857b1fadd774184dbd7547ccbf57a150110752eb1e119b34a2dfd18de499b18d03229f8617fca8d201fb977a4a1e1b0b3f1464d194b304abd76a0ccdc9889b24d838bc76a86eac93f8e8694005069e76e9051542a573fc02ff2d61a0b2b374a82a65642658b1c2c5b1b7a39aca7ff41e0391b4079c63445e6c0897fecf1989eb97ba3443325c20922835c191d561d849af9b3135a61fa7a36e8a5566ce22259ce678462399204f8b409283dff704af2e84d191051cd546d3afc552309e7ff5d4f1d86b85fef346f96b00b7","df312d181732efc50af13230e94f3ac7af7793e258bd9b7db97db5021eae68055831d9ade2969867d12a2ffda6589fd6fdb9e5fdde92e7d3ded58e103a62942d75c91ea251f23f2e5e61422955eb01b8b711661f856987bea07d14d22e64b72dce369a99eac43af5ea383e5ba27bc004ee74a5b6b7793cf0355b6a5531d2dec45c07ce24e92903ec61bbdba35b39ca58dbbe6b0c017760636b5d167293fb1db69e667f52fcb5ffe642c29cd661da8be2395948f64d0dfe76bd1781469fbd7e2f7afec80f3deaae32fab72222b4da66cc8322202e93d2b8582729339d6c213ad0db05a72b2b8f0aaa0fd9bcb563b24f19f466a39f99fdfa79f950ccec3657aa668663ec3de834f84b557a096723783b4e7924e343478bc90780c2e0f26685d4425ad99a207c86577596b92905b38227d80ef003f048d355812ca432f10561cf34d53e1dfd1b923a60c7274d8ae41e8ec379ff02c42affaa04a888c4bc3c2c1f5ff8e5794e136206863266e55bcd003777ae3d3669d56d7231422db6e7990c6bceee84a7cf913cc6904404da41d34bdc5b267c519c00c502d5c7f543154ebf85a583ce65ba810f9c67ee48faafc2176873d48d2a73e8629f5fa5d6ec2e43b17f0a767a84e75f064595976aad312bb11ce01d0ebbaae34ca544c0112ca3b0052d4063eda72e1db91ff1a202e3cf3b478638c493c25a0c42d5fc913414cd6566e6f9","01b8758d2e3cd42c7582c079bfb9606b5b749b350555d23ac999f6022f51b7bc270bee413f3db20513bdbc3bb0e90f9bf316da1bd7d53fc8dae78fd3f2082c505e2c897f14ef5383c2522d880963375c811db341edfe0eb0b94bd33423de71f09a2d3be19afa54f2be70071923c5d0be58a1ffed0fe637b937541ae74c5ef8ed2ad3b3d8632fabc64925f56471bf47ba98588d1e1c0b25bc49747379e6287b06fc3bd358c65a5fd54e03bae1a48d95f09e155cb907ac818c0ebb03582677e02cafa639da9d06e142d4e5e690ca9545aa199c61e3283ac81349ca8a978fcce9f011d1bf3608c58ace0e3bb7ae47573dd7f138aa3f137aff158b200f41c5bf943c9b6b5e94a82cb5c60da25978c7f7986790b9e1fb27ebeeb3ad50797c50bec60cb1c75b51fa57b28b77edf4cfe3d73f09685a00c524ea57d9f8895a492f3c6c625697ce0c4f5a7ac038e4a104d16f30a6f50be3d7c75999bb57740b4c6c4f94772b5f0556b413267881ef03fd39bccf22fbdb49316b44fdb60f0855bdf9bc983698c129eff6ef984aaa0eb7b30af2d7094306d0658c995a9f85136142356d3355066156809bcee013823b7c90b2ac00434f78a6468efb6ba6c6758d11f618ed79ee7993268e3638e60a89baf514cecd1e6d179a8346e5b25195e15f924e7fb6ce75a4e461169fe5af7ddfca8328bc16d711770c1ea310670175e68ae1eb6c9a5ec5","014a3d9de129fefcd4c6e20869ef73b2cd4b9b2b7b903c2dd2e863ec2034ec823f57311c2c65f5e1bdcb02e8b8554b66a3f8e845d818c220c04c2e7594dfde60c5e4fc40a4ce83aeff488432e2e3753bd89b30df646a15c92308584b63779ca1dd7646ce2520a8e5247754821552e02a2621c3c02a7cbb4da3d854eb95330a26f3598a3407142639620be65275467c46266a0536cf6093a9c35e76d5c25f80344f64f46b9e89970fe28550ee93d54de64570fa2e60419f872d3421e2b7df1df0f8c9affbe206795a6e00a8f04b787d4c0811fe76b1e025de7ee16bd98ff275c02fa763758f23caa11de33404f17a8f8674ddf7ce4856fc4c08d9ca76815366c59b59d2151994b04d4617e52c10f0042000188a883efbe06f1c6fed351fe6463e7d53d160574a1fa2fe7821f438c7ebfc1d7d77fc94b4345696ee9f401a837d94e0bbfbf1a384a76c48504b5e286ddb28916360dc891e4202cd651a3a404d2a0cc69f87e5205b591820e749197f39d16ea5915c829eea6fc30c995ff6935afb9376045372f7c7a9227ffc01045577b5f696001cf36b133c646c1b474a12049b669e511a933d7a6fada4aebb2ca0379e4a3b77fe7f2878450785c34f2624d7e2c279062e18c5e55faa3d392587016f552177efc5ba72af85a39aa20d147e50f3c81fc57fd679cb5c58acc0239ceec5b62527e48ed89f745de853744e800fe5791010"]
 p,q=wiener_attack(public_server_n,public_server_e)
 if p is None or q is None:
     print('Wiener Attack Failed Cannot Find Private Key')
     return None
 prRed(f'[*] Wiener Attack Success Factorize {public_server_n} with factors : ({p},{q})')
 msg_captured_int=list(map(lambda x:int(x,base=16),msg_captured_hex))
 phi=(p-1)*(q-1)
 d=inverse(public_server_e,phi)
 prCyan(f'[*] Private Key : ({public_server_n} , {d})')
 prGreen('[*] Start Decrypted Messages')
 for encrypted_msg in msg_captured_int:
     decrypted_msg=pow(encrypted_msg,d,public_server_n)
     prGreen(f'Encrypted Message : {encrypted_msg}')
     prGreen(f'Decrypted Message : {long_to_bytes(decrypted_msg).decode("utf-8")}')
     print('-'*50)
if __name__=="__main__":
    main()