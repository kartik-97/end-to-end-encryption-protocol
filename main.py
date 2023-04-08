import client
import server


def main():
    while(True):
        try:
            print("Choose one:")
            print("1. Run client A")
            print("2. Run client B")
            print("3. Run client C")
            print("4. Run server S")
            print("5. Exit (E)")
            print("input your corresponding choice (number or letter)")
            choice = input('management > ')

            if choice in ['1', 'A', 'a']:
                client.run('a')
            elif choice in ['2', 'B', 'b']:
                client.run('b')
            elif choice in ['3', 'C', 'c']:
                client.run('c')
            elif choice in ['4', 'S', 's']:
                server.run()
            elif choice in ['5', 'E', 'e']:
                break
            else:
                print("err > invalid input")
        except Exception as e:
            print('err >', e)


if __name__ == "__main__":
    main()
