"""
Python script to fetch Nifty 200 stocks data using yfinance.

This script fetches historical or real-time data for all Nifty 200 stocks
listed on the National Stock Exchange (NSE) of India.
"""

import yfinance as yf
import pandas as pd
import requests


def get_nifty200_tickers():
    """
    Fetch the latest list of Nifty 200 stock tickers from the NSE API.
    
    Returns:
        list: A list of Nifty 200 stock tickers with the '.NS' suffix.
    """
    url = "https://www.nseindia.com/api/equity-stockIndices?index=NIFTY%20200"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        tickers = [stock["symbol"] + ".NS" for stock in data.get("data", [])]
        return tickers
    except Exception as e:
        print(f"Error fetching Nifty 200 tickers: {e}")
        # Fallback to a predefined list if API fails
        return [
            "RELIANCE.NS", "TCS.NS", "HDFCBANK.NS", "ICICIBANK.NS", "INFY.NS",
            "HINDUNILVR.NS", "ITC.NS", "SBIN.NS", "BHARTIARTL.NS", "KOTAKBANK.NS",
            "LT.NS", "HCLTECH.NS", "MARUTI.NS", "SUNPHARMA.NS", "TITAN.NS",
            "NTPC.NS", "ASIANPAINT.NS", "BAJFINANCE.NS", "ONGC.NS", "JIOFIN.NS",
        ]


def fetch_stock_data(ticker, start_date, end_date):
    """
    Fetch historical data for a single stock using yfinance.
    
    Args:
        ticker (str): The stock ticker (e.g., 'RELIANCE.NS').
        start_date (str): Start date in 'YYYY-MM-DD' format.
        end_date (str): End date in 'YYYY-MM-DD' format.
    
    Returns:
        pd.DataFrame: Historical data for the stock, or None if an error occurs.
    """
    try:
        stock = yf.Ticker(ticker)
        data = stock.history(start=start_date, end=end_date)
        data["Symbol"] = ticker
        return data
    except Exception as e:
        print(f"Error fetching data for {ticker}: {e}")
        return None


def fetch_nifty200_data(start_date, end_date, output_file="nifty200_stocks_data.csv"):
    """
    Fetch historical data for all Nifty 200 stocks and save to a CSV file.
    
    Args:
        start_date (str): Start date in 'YYYY-MM-DD' format.
        end_date (str): End date in 'YYYY-MM-DD' format.
        output_file (str): Path to save the combined CSV file.
    
    Returns:
        pd.DataFrame: Combined data for all Nifty 200 stocks.
    """
    print("Fetching Nifty 200 tickers...")
    nifty200_tickers = get_nifty200_tickers()
    print(f"Found {len(nifty200_tickers)} tickers.")
    
    all_data = []
    for ticker in nifty200_tickers:
        print(f"Fetching data for {ticker}...")
        stock_data = fetch_stock_data(ticker, start_date, end_date)
        if stock_data is not None:
            all_data.append(stock_data)
    
    if not all_data:
        print("No data fetched. Check the tickers or your internet connection.")
        return pd.DataFrame()
    
    combined_data = pd.concat(all_data)
    combined_data.to_csv(output_file, index=True)
    print(f"Data saved to '{output_file}'")
    return combined_data


def fetch_nifty200_data_batch(start_date, end_date, output_dir="nifty200_data"):
    """
    Fetch historical data for all Nifty 200 stocks in bulk using yf.download().
    Saves each stock's data to a separate CSV file in the specified directory.
    
    Args:
        start_date (str): Start date in 'YYYY-MM-DD' format.
        end_date (str): End date in 'YYYY-MM-DD' format.
        output_dir (str): Directory to save individual CSV files.
    
    Returns:
        dict: A dictionary of DataFrames, where keys are tickers and values are their data.
    """
    import os
    
    print("Fetching Nifty 200 tickers...")
    nifty200_tickers = get_nifty200_tickers()
    print(f"Found {len(nifty200_tickers)} tickers.")
    
    try:
        print("Fetching data in bulk...")
        data = yf.download(
            tickers=nifty200_tickers,
            start=start_date,
            end=end_date,
            group_by="ticker",
            progress=True,
        )
        
        # Save each ticker's data to a separate CSV file
        os.makedirs(output_dir, exist_ok=True)
        for ticker in nifty200_tickers:
            if ticker in data:
                data[ticker].to_csv(f"{output_dir}/{ticker}.csv")
        
        print(f"Data saved to '{output_dir}/' directory.")
        return data
    except Exception as e:
        print(f"Error fetching data in bulk: {e}")
        return None


if __name__ == "__main__":
    # Example usage
    start_date = "2023-01-01"
    end_date = "2023-12-31"
    
    print("=" * 60)
    print("Fetching Nifty 200 stocks data using yfinance")
    print("=" * 60)
    
    # Option 1: Fetch and save combined data to a single CSV
    print("\nOption 1: Fetching combined data...")
    nifty200_data = fetch_nifty200_data(start_date, end_date)
    if not nifty200_data.empty:
        print("Combined data fetched successfully!")
        print(nifty200_data.head())
    
    # Option 2: Fetch data in bulk and save to separate files
    print("\nOption 2: Fetching data in bulk...")
    batch_data = fetch_nifty200_data_batch(start_date, end_date)
    if batch_data is not None:
        print("Bulk data fetched successfully!")
