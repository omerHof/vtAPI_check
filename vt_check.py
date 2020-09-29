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
      - vt_api_key = str, virus total api key
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

    self.vt_api_key = "b4e8ef265bdc9d5f25603cb9bf0436edb324aec64db43766881d7a7c39838b87"
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
  Find the percentage of malicious files for each indicator - if its below the threshold, removed it.  
    example:
    - malicious file => detection rate>20
    - amount of files to check = 300
    - threshold = 98%
    means that less than 6 files have a detection rate<20
  """
  def check_indicators_in_vt(self, indicators_list):

    self.verified_indicators_list=copy.deepcopy(indicators_list)
    for indicator in indicators_list:
      # validate to indicator for vt engine
      indicator = self.validate_indicator(indicator)
      #check if the indicator has been checked before
      if indicator in self.indicator_checked_dict:
        logging.info("malicious stats for " + indicator + ":")
        if (self.indicator_checked_dict[indicator]==False):
          self.remove_indicator(indicator)
          logging.info("indicator :" + indicator + " - was found BENIGN, according to previous checks")
        else:
          logging.info("indicator :" + indicator + " - was found MALICIOUS, according to previous checks")

        continue

      with vt.Client(self.vt_api_key) as client:
        logging.info("malicious stats for " + indicator + ":")
        check_benign = False
        total_results = self.get_matches_files_from_vt(client, indicator,check_benign)
        check_benign = True
        amount_of_benign = self.get_matches_files_from_vt(client, indicator,check_benign)
        if total_results>0:
          percentage_of_malicious = 100 - (amount_of_benign / total_results) * 100
          if percentage_of_malicious>self.threshold:
            logging.info("indicator: " + indicator + " - was found MALICIOUS because: ")
            logging.info("number of files found: " + str(total_results))
            logging.info("percentage of malicious hits: " + str(percentage_of_malicious) + "%")
            self.indicator_checked_dict[indicator] = True
          else:
            logging.info("indicator: " + indicator + " - was found BENIGN because: ")
            logging.info("less than " + str(self.threshold) + " % of the files found malicious")
            self.indicator_checked_dict[indicator] = False
            self.remove_indicator(indicator)
        else:
          logging.info("indicator: " + indicator + " - was found BENIGN because: ")
          logging.info("no results on vt from the last 3 months")
          self.indicator_checked_dict[indicator] = False
          self.remove_indicator(indicator)


    """
    get all benign results (less than malicious detection rate input) for an indicator - return a list of sha 256
    """
  def get_matches_files_from_vt(self, client, indicator,check_benign):
    """
    search api call params:
    query (require) = indicator query ,
    order = asc or desc (detection rate / file size )
    limit = max file that will be return from vt,
    batch_size = max file that return on each call from vt
    descriptors_only = hash only (not all file data)
    """
    query = 'type:peexe behavior:"{}"'
    query = query.format(indicator)
    if check_benign:
      query = query + "p:{}-"
      query = query.format(self.malicious_file_detection_rate)
    order = 'positives+'
    descriptors_only = 'true'
    try:
      it = client.iterator('/intelligence/search',
                           params={'query': query, 'order': order, 'descriptors_only': descriptors_only},
                           limit=self.vt_engine_amount_of_files_to_check,
                           batch_size=self.vt_engine_amount_of_files_to_check)
      results = 0
      for obj in it:
        results = len(it._items)
        break
      return results
    except Exception as e:
      logging.error(
        "Failed to check indicator : " + indicator + " in VT engine ERROR MSG: " + str(e))
      return

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
    v_indicator= v_indicator.replace('}', '')
    v_indicator= v_indicator.replace('{', '')
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
      copy_list = copy.deepcopy(self.verified_indicators_list)
      for verified_indicator in copy_list:
        if indicator in verified_indicator:
          self.verified_indicators_list.remove(verified_indicator)

    else:
      self.verified_indicators_list.pop(indicator)


if __name__ == '__main__':
  v =vt_check(299,98,20)
  v.start("C:\\Users\\ohoff\\Documents\\vt_check_repo\\repo_test\\Detection_Recommendation.json")
