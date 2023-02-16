from spid_sp_test.indicepa import get_indicepa_by_ipacode

def test_indicepa():
    get_indicepa_by_ipacode('unical')

def test_indicepa_2():
    res = get_indicepa_by_ipacode('r_vda')

def test_indicepa_3():
    res = get_indicepa_by_ipacode('cnpaf_0')