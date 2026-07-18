from mschf.app import main
import os

if __name__ == '__main__':
    try:
        main().main_loop()
    finally:
        os._exit(0)
