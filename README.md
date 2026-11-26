# Outline

## Lattice-based methods
The closest code for an implementation of lattice-based ABE is [here](https://github.com/RajWorking/CP-ABE), but it does not work in tests. The paper it is based on is:

```
An Efficient and Secure Post-Quantum Multi-Authority Ciphertext-Policy Attribute-Based Encryption Method Using Lattice (IEEE INFOCOM 2023).
```

This code does not run MA CP-ABE: [here](github.com/remigerme/CP-ABE?utm_source=chatgpt.com) or [here](https://github.com/eOnofri04/Cross-primitive-comparison-in-CP-ABE)

## Simple all-or-nothing share
For this, we have:

<img width="1174" height="862" alt="image" src="https://github.com/user-attachments/assets/65235341-8572-4932-9c17-aa23678ca861" />


The policy is:

"University:Researcher" ∧ "Company:Finance" ∧ "Company:Manager",

A sample run is:

```
Original message: Hello

Policy: ['Company:Finance', 'Company:Manager', 'University:Researcher']
ML-KEM ciphertext sizes:
Company:Finance 1088 bytes
Company:Manager 1088 bytes
University:Researcher 1088 bytes

Decrypted message: Hello
Missing attribute: access denied

Ciphertext JSON:
{
  "format": "ma-attribute-ml-kem-768-demo-v1",
  "policy": [
    "Company:Finance",
    "Company:Manager",
    "University:Researcher"
  ],
  "nonce": "dWctMFE91/JgQYeR",
  "ciphertext": "EXkrGI/Roke1MNdeSkhcVkslC4nC",
  "wrapped_shares": {
    "Company:Finance": {
      "kem_ciphertext": "zwJl0DsTe8IL7OrtmWoAhKOTioyquttcmBD/DvBoru6aaM1OmsEB1x1KMc8tdQssI3vF4U/lkIXFUtbqm7HkyaOkdccCJmJU2vLFn19Zwwk3fay3y3QEimiD9MklzgAGfj3fYdNURwAUfavmzXhJzv0bkvuRGEK1Is+grBawGQ7Wmkti7PCUTet0bsVS5WDVK+z5sVPbAyKPcuV4HuNZZAa+/1NZAzKe3HWgKVxM95rHY1odeGPEe/PHPBDJm4O1k5ssyNXO8GGCfpwozQtTjwmFz6iUSXsAF9Dg8BdIzTjyIEoxHg2H+tt0AYQKt9pMNA5v7/CX4MXQ17xX6kNQkKE7rbj5CNqYbkh2Pj/r9wKKZvAWtBOUv3tgWuTEmgOSzhyLVjIqInftjVmHaSKjtlJIikVvZEK0M+gsVQCsdXyg6ORpadE2CHSg5vUPmVGLC556FKSJpzxi8Cq4WMBugKN/qn7UMiGD6mSLU1MkgEOmGkXJeNB8b0T9tXeGf7+0Ebay8jhue9VvjuGmhOAMxH2nvsiU5IFsKDKbkzFq++egjdibhUqW15TLqZxQNFC5XTVpeJZtR8M9Jjf6Of5LlOAmXwWh4fehpNXQ48Db0Sy7azs6FaOvepGIogCLah2heIRwtjEGh7Vuv2YOFOY9pCzbONpO1y8cb1IKTsV9AqDeL/MIbbq9OVpkHLbpcVUxuhFHVfJFs29sVE+7D5JpRploU8yLO3Sdzt6WHw17EPZYbMo9YYnEQ2OqQAa9SkKX6j5wGVH4jebteRh5NjCjMbmi9FWxSyZisKUgC23fPhrRuAF15HwycGQgI9RYInpr+9srT7UUBKQf1NVRyZH1TOKqr/aQEbPDdVfAyolH29JuJqgmTtSfWrnGW7lnslm7kdP+ciPvx1eD9oqWPq3JDUyvbUkib42KOjFC7ROno6XLldZU+yNMzs32O3apSJ3vyORG56TlD04TWOFwoQyCRpmPAl5zXvnx1vjN+Lmri45LrL3M7MgPgpv8j5nj2ve3RDaT4EEaSOBkjc5yWOMGRHE/B4VHus5Kwf8RCEa/uwCsDQxIMSDhiJyjLlizLNSLQbLzTnvojlmZHg89f8m33UT9jOD1nHhs6ubW1KX4tZCkWL4r3+nzS3UW3wwbH9y+YdClX9pxbPzcmNjM3l7f9hRyf7WABOz8thaJ6VQ8nMuWObCCBifLnnvKESgYdLYbBlexh0Y9cOWMyXewGEsjMETFV9Q9Qk7XBESykcb53Cyew/1PxAJmbI2JqIrjE83EWB+0cGpPRJAQrfmr4NDDFcM3UgocMCk7gek+XLneLKkLXMR7nPuoh0x9zsKk5AbszjZx/rovJBd4w7KJeBwV1WeGen/1eZ28aqyzr0izZFQpziL1+zjP8DFfp2KxgXiOucTG7SAP/jwPp6bsOyBZjM/9dPFpgrYzUkmhPrODI+E=",
      "nonce": "tAnAIZ/1ekisb/QJ",
      "payload": "f54it7TB6F2JuRS2/xDV14OUh6XlOhFD12mCQypwFSQ3nvZszugkb52OC4ZXsd5F"
    },
    "Company:Manager": {
      "kem_ciphertext": "mg2b4B6mncbnYmqtN7dNCk/QVZcQwZS++eB92ExyVnsv0yf2zg2TfJNpppnopKuQcCeYijxV+906tKUBfIBudcEaI2wE7HHK+sEOoNCVXklsolJgUgx7m75OIxIcgBoj/d+V6y2kZeTRYXdUhUZNDWq+1Hi9tf4XKBRd4SEmTisOzBqvWLQCjdzY0B8EYexloAVg8A39PCgSC0RGLC5PG6UpOEq/63dCaypYIEsaygpsq11baeSm89vZFTNygPPaFc3KJH+avf8qa4eOQCdDnB3aRQss0HOXtuutRXv/ZbP+ssYG1EYfNeC+LZWrhcE5LTv+vMwhfXGjAQt5yNmYAavg7AHNoyJpMbXHrtqtCySiZvXO2XN/es7ZDyyCWaDZArheS5BaeyyUTNF1jZuvtkxKNZFQVtKC2+ywGJ5jm9HhdRPMbyWyE7HydEn6pZEht8lMKIHcen60AG4Mk3DWlgkQuuZyb3j7mQh6g6yZYMlj2Bs05KTtxqtS48BQHDX7xrErYvGojMHMyE/LFT3DWmuyCvOBIjQY4ky+vbYdALuD/YsZ24aet5wNqXzSovqml1RkRGi2T1RwiW3vZGb2j7Rt0q9n6kEC4yoGKeBgUFEV83+D4GO9jCwmOY9AMHFOpI+NrPZmJZkK2AXgxta0ZkqawH2Fovo7X8YcF82AHi+xpzUeTo2bKNasKiQh3hbqj+9tKHfZY7v+hY2dg7tTGNgH4ZE8ZWrgADfpMj9OVD/2i1daQrvQ/26VIiluggblRDQgyGycpkusOdl6PZ2K9SPkkxkjWpeTkfzKfuzMmH0Egud/Kz24Sqhj6BS3pDppbDGizedMdXpxcSD9TR19nauu3iiHktSj7wWLFkRVZSmOfgZcEjZvQ9N9kWKoBKQ0Htwx/pFybddrP0AJ+97Rx2VMbMKDaYtIAvyFDgZl4n6jet1UKspAlDLH5ky426e7mZJ2wbarz+H/AQ/UtDQ5KKEVPAAJJuPyub51siBb8QNXYFj6wX7RJOpg9+jFXV59oXtxC8MO3exiZRZh7oybGr/7pB2pH1xy5a0uKe4j28Rcr6ntJwHyYSOy5AaopItm604eFoJZCC2MlbP5d4T22xhPtSnRNsnY9OqRfOWbClFML0D+0wx1IwuaPpnUgY+imGBG3NicTC04AX8rAIVktES1kZFWNhdDDWSUlGN+M3B0tyGwoPvfFLsX/ANdwcQ3vHR39PRkLht1box2X/IBJPw6ncSmJyN6Q4U4CW1NJHuniXFfCVL6cHKXApTHvnKcUEjfGFLHsxx5P3p25P41eVOFJdFmnJ2rI2jbBEcWJdnTFz+E7t+l5vOKPh9lvvh2fmEz4WQOf3JlWQh6Qz7uiyxQzq09cHeutmwL7zYn/8SXP4nfMBLxCYZ5M+8zscKMwP0g+ZNL8rADp6VSrKVyZk63fh9ryeQfCqKMlrW+0NY=",
      "nonce": "DBPuxSRqDiQXNrqB",
      "payload": "YMgmlldBQu5RtDxM2bdVMozhnA3xY889+HOsel11Xk8XxxPDk3kaO/W1fbcNKjUt"
    },
    "University:Researcher": {
      "kem_ciphertext": "C1ggFR1JRm4B4nlLMpqTPjd5Tvf0SfF5WqkKk/jm+uKSmCVez5eypHA7V43/Oe6Lgg/vvFeZtJXK4HtkneRsJoc2xSRrKKfFzB+C5OitLb6S5XprWrI8RE5FonIH231yxtEIdSKoPmqGh4EGS5AV6XBFfwfx/jbdC9QcRrBSI1Bi5yUIKAvZd9MjvP40jNDRGjTOMpQiy+FPe/AqxXyR8VZ8wxgB2QzWUNb6qS21AkhsfM4eG/E+VwHl28uB4P4rxjOC8iO5RZ7E2VYZJuITepnTRc3HOWq6KeaRnPy6P+otdfn4CWdYZBQlzCj2Xo8Sh3yVKWrG7ucJeqq/dD6XRpqrVuIlT4usE+AdHjGnEF1gAMJkZKD2Kw8zJ4cVsaT8Dfejhk/QZIkT/nyRK+Nqxg8VxaXsVxFZNWyaxhy44RtrnLcl6rRk9Y6eQW1surGb8pySitU7gUdTvNMjP34f6yXD/ea8h9zxWPVYFS/h70qJ3d1+mPFY8yAkrILFjxMKm3dpPkvmnudPskgMtq5iZfNZVgqnhz7Lt6gCDmJIeWFLT9wAbdluc6T08sOAtO7sWtbXGmh5LrSc6v+v2R/rQ3mr93n5eLvCbPOiIA9zigq7Wzoy41XNaS9RnUROTsdevQCdZt/M8FmhPWSBE8imw5Tdsxo/+Tjez0vUzS3q7yIpL/npWFCGfSldw8qgAb7AvPqTz/RtQ7ARgRfJQ75pQm9mr0sahHqsnrrY8CVU+smMSVpgTdCOmdJuloyx3s56tE8zj2ThGLSoTuFQEZEBvP7NRHv8Off+KbDVK+v1LpBF2S/JATySgb/xG1tvwQ/uBaOPCMJW9WscOC0Bhr5Crl4Tg73E4BpPuD6C4+Ds7PzZmQo2cR0svguoWBnk3M4H2ZSMSMvfvwUCMe1YVLpR5/zbh5m4W0NzIRv1l8nXW3zIUZ+Jg/5Vn8tKth5X1mwOAGO/oe7iVugY+8EQvpUFCC0dIZN4ffzs9HD+mlNfDoYnZpBWHdiuM2DExqBlTwiyXUbaXFiChFeU6seQQNiGSngOnQCzr50FdZYIEH5e/g+4KuapRqYoyH4BDqkYrni+t8/cp+eY/Xhsv6ZbkHiYp2PEUQhRRK3seSn4jexqaB6ggmTKQKelNMzZi+LMLdtVZFTmZFNT4VCGXCP6p3pPvfoVs5uP5yYirf5znJE6pxVVlkiL1GWJiA1l+ETZkFrdeV/PR/NANgSZwcN8F7aq3/nXmGvxuL0WO3Ap/PPweT1vois3x1V0KrApDTnw/VhEaWPH/ltW7if8RRVWYgRcw209ogJRCZVePNHvF2OZKJh0py/JI1ochgTwIcYY74JD5FdAcKjnz3Du2kdjnxhycz+NAE032uNKgnfz5ZndBc4wx+kYIh1gOTH8SYObFcBedL+J1OeAFmiz0ky5HKBQc68KM8I1ceH8ydZ3GJogX0Q=",
      "nonce": "zuf0IIZFMMPKQ5tX",
      "payload": "+qtmbE2wGfRIqxug23agnTBxIldGqL7K2uA5ppD20VP+HFOtYlrj5Oc1h+Zw3FLu"
    }
  }
}
```

## Non-collusion PQC ABE
The problem with this code is that the authorities can collude to rebuild the key. With the second code example [here](https://github.com/billbuchanan/cp_abe/blob/main/main2_nocol.py), we overcome collusion:

```

Policy: ['Company:Finance', 'Company:Manager', 'University:Researcher']
Authorised recipients: ['Dave']
Dave decrypts: b'Hello'
Alice access denied
Bob access denied
Carol access denied
Colluders eligible: False
Collusion test complete
```
