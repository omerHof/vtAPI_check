import vt
import json
import os
import logging
import copy

class vt_check:

  def __init__(self,amount_of_files_to_check,threshold,malicious_file_detection_rate):
    """
    class variables:
      - vt_engine_amount_of_files_to_check: int, amount of file that will return from VT behaviour check (max 300!)
      - malicious_file_detection_rate: int, the number of detection rate that determine that a file is malicious (max 69!)
      - threshold: int, the percentage of malicious files in the returned files (max 100!)
      - path_to_recommendation: str, input file Detection_recommendation
      - indicator_checked_dict: dict, all the indicators that all ready been checked in vt for the current session
      - verified_indicators_list: list, the verified indicator for each section
    """

    self.vt_engine_amount_of_files_to_check = amount_of_files_to_check
    if self.vt_engine_amount_of_files_to_check > 299:
      self.vt_engine_amount_of_files_to_check = 299
    self.malicious_file_detection_rate = malicious_file_detection_rate
    if self.malicious_file_detection_rate>69:
      self.malicious_file_detection_rate = 69
    self.threshold = threshold
    if self.threshold>100:
      self.threshold =100

    self.path_to_recommendation = ""
    self.indicator_checked_dict = {}
    self.verified_indicators_list =[]

    # Configure the logging system
    logging.basicConfig(filename='logger.log',
                        level=logging.DEBUG,
                        format = '%(levelname)s:%(asctime)s:%(message)s')



  def start(self, path_to_recommendation):
    logging.info("Start VT check to reduce indicators")
    self.path_to_recommendation = path_to_recommendation
    recommendation_file = open(self.path_to_recommendation)
    recommendation_data = json.load(recommendation_file)

    if "Level_1" in recommendation_data:
      logging.info("Level 1 VT check")
      recommendation_data["Level_1"] = self.level_check(recommendation_data["Level_1"])
      if len(recommendation_data["Level_1"])==0:
        del recommendation_data["Level_1"]

    if "Level_2" in recommendation_data:
      logging.info("Level 2 VT check")
      recommendation_data["Level_2"] = self.level_check(recommendation_data["Level_2"])
      if len(recommendation_data["Level_2"]) == 0:
        del recommendation_data["Level_2"]

    with open('recommendation_data.json', 'w') as outfile:
      json.dump(recommendation_data, outfile, indent=4,)


  """
  check each indicator for each level
  """
  def level_check(self, level):
    delete_list = []
    for key in level:
      self.check_indicators_in_vt(level[key])
      if self.verified_indicators_list:
        if len(self.verified_indicators_list) != len(level[key]):
          level[key] = self.verified_indicators_list
      else:
        delete_list.append(key)
    level = self.clean_indicator_list(level, delete_list)
    return level



  """
  main function 
  Find the percentage of malicious files for each indicator - if its below the threshold removed it.  
    - malicious file => detection rate>20)
    - threshold = 98%
  """
  def check_indicators_in_vt(self, indicators_list):
    # vt api key
    apikey = "b4e8ef265bdc9d5f25603cb9bf0436edb324aec64db43766881d7a7c39838b87"
    self.verified_indicators_list=copy.deepcopy(indicators_list)
    for indicator in indicators_list:
      # validate to indicator for vt engine
      indicator = self.validate_indicator(indicator)
      #check if the indicator has been checked before
      if indicator in self.indicator_checked_dict:
        if (self.indicator_checked_dict[indicator]==False):
          self.remove_indicator(indicator)
        continue

      query = 'type:peexe behavior:"{}"'
      query = query.format(indicator)
      order = 'positives+'
      with vt.Client(apikey) as client:
        """
        search api call params:
        query (require) = indicator query , 
        order = asc or desc (detection rate / file size ) 
        limit = max file that will be return from vt, 
        batch_size = max file that return on each call from vt 
        """

        try:
          it = client.iterator('/intelligence/search',
              params={'query': query, 'order':order},
              limit = self.vt_engine_amount_of_files_to_check,
              batch_size= self.vt_engine_amount_of_files_to_check)
          logging.info("malicious stats for " + query + ":")
          counter = 0

          for obj in it:
            if obj.last_analysis_stats['malicious']<self.malicious_file_detection_rate:
              counter = counter+1
            else:
              percentage_of_malicious = 100 - (counter/len(it._items)*100)
              logging.info("number of files found: " + str(len(it._items)))
              logging.info("percentage of malicious hits: " + str(100 - (counter/len(it._items)*100)) + "%")
              if percentage_of_malicious<self.threshold:
                self.remove_indicator(indicator)
                self.indicator_checked_dict[indicator] = False
                logging.info("less than " + str(self.threshold) + " % of the files found malicious")
              else:
                self.indicator_checked_dict[indicator] = True
              break

          if indicator not in self.indicator_checked_dict:
            logging.info("indicator :" + indicator + " - was found benign")
            if it._count>0:
              logging.info("less than " + str(self.threshold) + " % of the files found malicious")
            else:
              logging.info("no results on vt from the last 3 months")
            self.indicator_checked_dict[indicator] = False
            self.remove_indicator(indicator)

        except:
          logging.error("Failed to check indicator :" + indicator + "in VT engine")

  """
  validate that the indicator suitable for VT engine - if not change it
  """

  def validate_indicator(self,indicator):
    v_indicator = indicator
    if "Administrator" in indicator:
      v_indicator = os.path.basename(indicator)
      temp_list = copy.deepcopy(self.verified_indicators_list)
      for idx, item in enumerate(self.verified_indicators_list):
        if indicator in item:
          temp_list[idx] = v_indicator
      self.verified_indicators_list = temp_list
    v_indicator= v_indicator.replace('"', '')
    return v_indicator

  """
  remove false sections from detection recommendation file
  """

  def clean_indicator_list(self, level_1, delete_list):
    for key in delete_list:
      try:
        del level_1[key]
      except:
        continue
    return level_1

  def remove_indicator(self, indicator):
    if type(self.verified_indicators_list) is list:
      if indicator in self.verified_indicators_list:
        self.verified_indicators_list.remove(indicator)

    else:
      self.verified_indicators_list.pop(indicator)



if __name__ == '__main__':
  v =vt_check(300,98,20)
  v.start("C:\\Users\\ohoff\\Documents\\vt_check_repo\\Detection_Recommendation.json")
