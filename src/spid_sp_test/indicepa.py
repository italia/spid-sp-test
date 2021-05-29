import requests
import logging


API_URL = 'https://indicepa.gov.it/PortaleServices/api/aoo'
logger = logging.getLogger(__name__)


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

    response = None
    try:
        response = requests.post(
                    API_URL, headers=header, data=qs_final, timeout=5)
    except Exception as e:
        logger.error(e)
        return {-1, {}}
    else:
        res = response.json()
        try:
            result = (
                res['risposta']['paginazione']['numeroRigheTotali'],
                res
            )
            return result
        except KeyError:
            logger.error(f"{API_URL} invalid response")
            return {-1, {}}
