#-*- coding : utf-8-*-
# coding:unicode_escape
import json
import nmap
import threading


class NmapScanner:
    def __init__(self, _host, save_path):
        self.host = _host
        self.scanner = nmap.PortScanner()
        self.save_path = save_path

    def run(self):
        with open(self.save_path, mode="a") as save_file:
            try:
                self.scanner.scan(hosts=self.host, arguments="-T4 -A -v -sS -sV --script-args http.useragent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0'")
            except UnicodeDecodeError:
                print(f"{self.host}: UnicodeDecodeError")
                ip_with_problems.append(self.host.replace("'", '"'))
                return
            try:
                a = bool(self.scanner[self.host]['portused'])
            except:
                a = False
            if not a:
                ip_with_problems.append(self.host.replace("'", '"'))
                return
            else:
                temp = {}
                self.host.replace("'", '"')
                temp[f"{self.host}"] = {}
                for x in self.scanner[self.host].all_protocols():
                    for y in self.scanner[self.host][x].keys():
                        temp[f"{self.host}".replace("'", '"')][f"{str(y)}".replace("'", '"')] = {}
                        temp[f"{self.host}".replace("'", '"')][f"{str(y)}".replace("'", '"')]["state"] = (
                            self.scanner[self.host][x][y]["state"].replace("'", '"'))
                        temp[f"{self.host}".replace("'", '"')][f"{str(y)}".replace("'", '"')]["reason"] = (
                            self.scanner[self.host][x][y]["reason"].replace("'", '"'))
                        temp[f"{self.host}".replace("'", '"')][f"{str(y)}".replace("'", '"')]["name"] = (
                            self.scanner[self.host][x][y]["name"].replace("'", '"'))
                        temp[f"{self.host}".replace("'", '"')][f"{str(y)}".replace("'", '"')]["product"] = (
                            self.scanner[self.host][x][y]["product"].replace("'", '"'))
                        temp[f"{self.host}".replace("'", '"')][f"{str(y)}".replace("'", '"')]["version"] = (
                            self.scanner[self.host][x][y]["version"].replace("'", '"'))
                        temp[f"{self.host}".replace("'", '"')][f"{str(y)}".replace("'", '"')]["extrainfo"] = (
                            self.scanner[self.host][x][y]["extrainfo"].replace("'", '"'))
                        temp[f"{self.host}".replace("'", '"')][f"{str(y)}".replace("'", '"')]["conf"] = (
                            self.scanner[self.host][x][y]["conf"].replace("'", '"'))
                        temp[f"{self.host}".replace("'", '"')][f"{str(y)}".replace("'", '"')]["cpe"] = (
                            self.scanner[self.host][x][y]["cpe"].replace("'", '"'))
                print(temp)
                save_file.write(json.dumps(temp) + ",\\n")
                save_file.flush()


if __name__ == '__main__':
    with open("target.txt", "r") as target:
        hosts = target.read().splitlines()
    target.close()
    path = "outcome.json"
    ip_with_problems = [] 
    with open(path, "w+") as file:
        file.write("[")
    for i in hosts:
        out = NmapScanner(i, save_path=path)
        out_ = threading.Thread(target=out.run())
        out_.start()
    with open(path, "a+") as file:
        file.write('{"ip_with_problems":' + json.dumps(ip_with_problems)+"}\\n")
        file.write("]")
