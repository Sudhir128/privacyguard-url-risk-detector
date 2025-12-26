from browser_history.browsers import Edge
import datetime,pandas as pd

def getbrowserhistory():
    edge=Edge()
    hist=edge.fetch_history()
    df=pd.DataFrame(hist.histories,columns=['datetime','url','title'])
    print("bh module is running")
    print(df)
    return df

if __name__ == "__main__":
    getbrowserhistory()