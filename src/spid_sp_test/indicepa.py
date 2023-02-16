import logging
import requests


API_URL = "https://www.indicepa.gov.it/PortaleServices/api/ente/ricerca"
logger = logging.getLogger(__name__)


def get_indicepa_by_ipacode(value):
    qs = """
    {"paginazione":
        {"campoOrdinamento":"idEnte",
         "tipoOrdinamento":"asc",
         "paginaRichiesta":1,
         "numTotalePagine":null,
         "numeroRigheTotali":null,
         "paginaCorrente":null,
         "righePerPagina":null},
         "codiceFiscaleRicerca":null,
         "area":null,
         "denominazione":null,
         "codEnte":"$IPACode",
         "idTipoServizioDigitale":null,
         "lingueMinoritarie":null,
         "codiceCategoria":null
    }"""

    qs_final = qs.replace("$IPACode", value)
    header = {"Content-Type": "application/json"}

    response = None
    try:
        response = requests.post(API_URL, headers=header, data=qs_final, timeout=5)
    except Exception as e:  # pragma: no cover
        logger.error(e)
        return [-1, {"errore": f"{e}"}]
    else:
        res = response.json()
        try:
            nrt = res["risposta"]["paginazione"]["numeroRigheTotali"]
            result = (nrt, res)
            if nrt <= 0:
                return [-1, {"errore": f"risultato vuoto per {qs_final}"}]
            else:
                return result
        except KeyError as e:  # pragma: no cover
            logger.error(f"{API_URL} invalid response")
            return [-1, {"errore": f"{e}"}]
