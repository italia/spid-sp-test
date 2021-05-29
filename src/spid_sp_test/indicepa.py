import requests

API_URL = 'https://indicepa.gov.it/PortaleServices/api/aoo'

def get_indicepa_by_ipacode(value):
    qs = '''
    {"paginazione":
        {"campoOrdinamento":"codAoo",
         "tipoOrdinamento":"asc",
         "paginaRichiesta":1,
         "numTotalePagine":null,
         "numeroRigheTotali":null,
         "paginaCorrente":null,
         "righePerPagina":null},
         "codiceFiscale":null,
         "codUniAoo":null,
         "desAoo":null,
         "denominazioneEnte":null,
         "codEnte":"$IPACode",
         "codiceCategoria":null,
         "area":null
    }'''

    qs_final = qs.replace('$IPACode', value)
    header = {"Content-Type": "application/json"}
    response = requests.post(API_URL, headers=header, data=qs_final)

    res = False
    try:
        res = response.json()
    except KeyError:
        pass

    result = (
        res['risposta']['paginazione']['numeroRigheTotali'],
        res
    )

    return result
