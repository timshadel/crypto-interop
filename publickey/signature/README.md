# Transmit Digital Signature

## How do I create a digital signature and send it to another app?

Each of our command line applications will have this form

    # Each app will be able to sign data
    $ <app> sign /path/to/data /path/to/private/key

    # Each app will be able to verify a signature over data
    $ <app> verify /path/to/data /path/to/signature /path/to/public/key
