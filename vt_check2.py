import vt


def main():
  indicators_list = ["shimeng.dll",
                     "esent.dll"]
  indicators = ["asxml6.dll", "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\koekuky.exe", "Yd9dH99P",
                ".*\\\\appdata\\\\local\\\\temp\\\\ellighixoqdjz"]

  # indicators = ["C:\\Users\\Administrator\\AppData\\Local\\Temp\\koekuky.exe","C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\koekuky.exe","Yd9dH99P",".*\\\\appdata\\\\local\\\\temp\\\\ellighixoqdjz"]
  # vt api key
  apikey = "b4e8ef265bdc9d5f25603cb9bf0436edb324aec64db43766881d7a7c39838b87"

  """
  Find the percentage of malicious files for each indicator 
  """
  verified_indicators_list = []
  for indicator in indicators_list:
    query = 'type:peexe behavior:"{}"'
    query = query.format(indicator)
    limit = 10
    order = 'positives+'

    with vt.Client(apikey) as client:
      """
      search api call params:
      query (require) = indicator query , 
      order = asc or desc (detection rate / file size ) 
      limit = max file that will be return from vt, 
      batch_size = max file that return on each call from vt 
      """

      it = client.iterator('/intelligence/search',
                           params={'query': query, 'order': order},
                           limit=limit,
                           batch_size=10)
      print("malicious stats for " + query + ":")
      counter = 0
      try:

        for obj in it:
          if obj.last_analysis_stats['malicious'] < 20:
            counter = counter + 1
          else:
            percentage_of_malicious = 100 - (counter / len(it._items) * 100)
            print("number of files found: " + str(len(it._items)))
            print("percentage of malicious hits: " + str(100 - (counter / len(it._items) * 100)) + "%")
            if percentage_of_malicious > 98:
              verified_indicators_list.append(indicator)
            break
      except:
        print("check failed")


if __name__ == '__main__':
  main()
