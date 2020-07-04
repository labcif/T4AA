"""
Autopsy Forensic Browser
Copyright 2019-2020 Basis Technology Corp.
Contact: carrier <at> sleuthkit <dot> org
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from java.sql import SQLException
from java.util.logging import Level
from java.util import ArrayList
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import AppSQLiteDB
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskCoreException
from org.sleuthkit.datamodel.Blackboard import BlackboardException
from org.sleuthkit.autopsy.casemodule import NoCurrentCaseException
from org.sleuthkit.datamodel.blackboardutils import CommunicationArtifactsHelper
from TskMessagesParser import TskMessagesParser
from TskContactsParser import TskContactsParser
from org.sleuthkit.datamodel import CommunicationsManager 

import traceback
import general
import json

class TiktokAnalyzer(general.AndroidComponentAnalyzer):
    """
        Parses the Tiktok databases for TSK contact, message 
        and calllog artifacts.
    """
   
    def __init__(self):
        self._logger = Logger.getLogger(self.__class__.__name__)
        self._TIKTOK_PACKAGE_NAME = "com.zhiliaoapp.musically"
        self._PARSER_NAME = "Tiktok Parser"
        self._VERSION = "15.0.1"

        communication_manager = Case.getCurrentCase().getSleuthkitCase().getCommunicationsManager()

        self.account = CommunicationsManager.addAccountType(communication_manager,"Tiktok", "Tiktok")

    def analyze(self, dataSource, fileManager, context):
        self.dataSource = dataSource
        """
            Extract, Transform and Load all TSK contact, message
            and calllog artifacts from the Tiktok databases.
        """
        try:
            calllog_and_message_dbs = AppSQLiteDB.findAppDatabases(dataSource,
                    "%_im.db", False, self._TIKTOK_PACKAGE_NAME)

            contact_dbs = AppSQLiteDB.findAppDatabases(dataSource,
                    "db_im_xx", True, self._TIKTOK_PACKAGE_NAME)
            
            # Extract TSK_CONTACT information
            for contact_db in contact_dbs:
                current_case = Case.getCurrentCaseThrows()
                helper = CommunicationArtifactsHelper(
                        current_case.getSleuthkitCase(), self._PARSER_NAME,
                        contact_db.getDBFile(), self.account)
                self.parse_contacts(contact_db, helper)

            for calllog_and_message_db in calllog_and_message_dbs:
                current_case = Case.getCurrentCaseThrows()
                helper = CommunicationArtifactsHelper(
                        current_case.getSleuthkitCase(), self._PARSER_NAME,
                        calllog_and_message_db.getDBFile(), self.account)
                # self.parse_calllogs(calllog_and_message_db, helper)
                self.parse_messages(calllog_and_message_db, helper)

        except NoCurrentCaseException as ex:
            #If there is no current case, bail out immediately.
            self._logger.log(Level.WARNING, "No case currently open.", ex)
            self._logger.log(Level.WARNING, traceback.format_exec())
        
        # Clean up open file handles.
        for contact_db in contact_dbs:
            contact_db.close()

        for calllog_and_message_db in calllog_and_message_dbs:
            calllog_and_message_db.close()

    def parse_contacts(self, contacts_db, helper):
        try:
            contacts_parser = TiktokContactsParser(contacts_db)
            while contacts_parser.next():
                helper.addContact(
                contacts_parser.get_contact_name(),
                contacts_parser.get_phone(),
                contacts_parser.get_home_phone(),
                contacts_parser.get_mobile_phone(),
                contacts_parser.get_email(),
                contacts_parser.get_other_attributes()
                )
                
            contacts_parser.close()

        except SQLException as ex:
            self._logger.log(Level.WARNING, "Error querying the Tiktok database for contacts.", ex)
            self._logger.log(Level.WARNING, traceback.format_exc())
        except TskCoreException as ex:
            self._logger.log(Level.SEVERE, 
                    "Error adding Tiktok contact artifacts to the case database.", ex)
            self._logger.log(Level.SEVERE, traceback.format_exc())
        except BlackboardException as ex:
            self._logger.log(Level.WARNING, 
                    "Error posting contact artifact to the blackboard.", ex)
            self._logger.log(Level.WARNING, traceback.format_exc())

    def parse_messages(self, database, helper):
        try:
            messages_parser = TiktokMessagesParser(database)
            while messages_parser.next():
                helper.addMessage(
                                        messages_parser.get_message_type(),
                                        messages_parser.get_message_direction(),
                                        messages_parser.get_phone_number_from(),
                                        messages_parser.get_phone_number_to(),
                                        messages_parser.get_message_date_time(),
                                        messages_parser.get_message_read_status(),
                                        messages_parser.get_message_subject(),
                                        messages_parser.get_message_text(),
                                        messages_parser.get_thread_id()
                                    )
            messages_parser.close()
        except SQLException as ex:
            self._logger.log(Level.WARNING, "Error querying the tiktok database for contacts.", ex)
            self._logger.log(Level.WARNING, traceback.format_exc())
        except TskCoreException as ex:
            self._logger.log(Level.SEVERE, 
                    "Error adding tiktok contact artifacts to the case database.", ex)
            self._logger.log(Level.SEVERE, traceback.format_exc())
        except BlackboardException as ex:
            self._logger.log(Level.WARNING, 
                    "Error posting contact artifact to the blackboard.", ex)
            self._logger.log(Level.WARNING, traceback.format_exc())

class TiktokContactsParser(TskContactsParser):
    """
        Extracts TSK_CONTACT information from the Tiktok database.
        TSK_CONTACT fields that are not in the Tiktok database are given 
        a default value inherited from the super class. 
    """

    def __init__(self, contact_db):
        super(TiktokContactsParser, self).__init__(contact_db.runQuery(
                 """
                    select UID, UNIQUE_ID, NICK_NAME from SIMPLE_USER;"
                 """                                                         
             )
        )
    
    def get_other_attributes(self):
        additionalAttributes = ArrayList()
        additionalAttributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID, "Tiktok Parser", self.result_set.getString("uid")))
        additionalAttributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, "Tiktok Parser", "https://www.tiktok.com/@{}".format(self.result_set.getString("unique_id"))))
        additionalAttributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_ID, "Tiktok Parser", self.result_set.getString("unique_id")))
        return additionalAttributes
    
    def get_contact_name(self):
        return self.result_set.getString("nick_name")

class TiktokMessagesParser(TskMessagesParser):
    """
        Extract TSK_MESSAGE information from the Tiktok database.
        TSK_CONTACT fields that are not in the Tiktok database are given
        a default value inherited from the super class. 
    """

    def __init__(self, message_db):
        super(TiktokMessagesParser, self).__init__(message_db.runQuery(
                 """
                    select conversation_id, created_time, content, read_status, local_info, type, case when deleted = 0 then 'Not deleted' when deleted = 1 then 'Deleted' else deleted end, sender from msg order by created_time;"
                 """
              )
        )
        self._TIKTOK_MESSAGE_TYPE = "Tiktok Message"
        self.uid = message_db.getDBFile().getName().split('_im.db')[0]
        self._message_db = message_db


    def get_participant1(self):
        dump = self.result_set.getString("conversation_id")
        splitted = dump.split(':')
        if len(splitted) > 3:
           return dump.split(':')[2]
        
        return ""

    def get_participant2(self):
        dump = self.result_set.getString("conversation_id")
        splitted = dump.split(':')
        if len(splitted) > 4:
           return dump.split(':')[3]
        
        return ""

    def get_conversation_id(self):
        return str(self.result_set.getLong("conversation_id"))

    def get_message_type(self):
        return self._TIKTOK_MESSAGE_TYPE
    
    def get_message_subject(self):
        message_type_id = self.result_set.getLong("type")
        if  message_type_id == 7: return "text"
        if  message_type_id == 8: return "video"
        if  message_type_id == 5: return "gif"
        if  message_type_id == 15: return "gif"
        if  message_type_id == 22: return "audio"
        if  message_type_id == 25: return "profile"
        if  message_type_id == 19: return "hashtag"
        return "unknown"


    def get_phone_number_to(self):
        p1 = self.get_participant1()
        p2 = self.get_participant2()
        
        if str(self.result_set.getLong("sender")) == p1:
            return self.get_user_uniqueid_by_id(p2)
        
        return self.get_user_uniqueid_by_id(p1)

    def get_phone_number_from(self):
        return self.get_user_uniqueid_by_id(self.result_set.getString("sender"))

    def get_message_direction(self):
        sender = str(self.result_set.getLong("sender"))

        if self.uid == sender:
            return self.OUTGOING
        return self.INCOMING

    def get_message_date_time(self):
        return self.result_set.getLong("created_time") / 1000

    def get_message_text(self):
        message = self.result_set.getString("content") 
        message_type = self.result_set.getLong("type") 
        message_dump = json.loads(message)
        body = self.parse_body_message_by_id(message_type, message_dump)
        
        if body is None:
            message = super(TiktokMessagesParser, self).get_message_text()
        return body

    def get_message_read_status(self):
        if self.get_message_direction() == self.INCOMING: 
            if self.result_set.getInt("read_status") == 0:
                return self.READ
            else:
                return self.UNREAD
        return super(TiktokMessagesParser, self).get_message_read_status()

    def get_user_uniqueid_by_id(self, uid):

        # database = AppSQLiteDB.findAppDatabases(self.dataSource, "db_im_xx", True, self._TIKTOK_PACKAGE_NAME)
        
        # name = database.execute_query("select UNIQUE_ID from SIMPLE_USER where uid={}".format(uid))
        # if name:
        #     name = name[0][0]
        # else:
        #     name = None

        # database.close()
        return str(uid)
    
    @staticmethod
    def parse_body_message_by_id(message_type, message_dump):
        body=""
        if  message_type == 7:
            body = message_dump.get("text")
        elif message_type == 8:
            body= "https://www.tiktok.com/@tiktok/video/{}".format(message_dump.get("itemId"))
        elif message_type == 5:
            body=message_dump.get("url").get("url_list")[0]
        elif message_type == 15:
            body=message_dump.get("joker_stickers")[0].get("static_url").get("url_list")[0]
        elif message_type == 25:
            body = "https://www.tiktok.com/@{}".format(message_dump.get("desc")) # or body = "https://m.tiktok.com/h5/share/usr/{}.html".format(message_dump.get("uid"))
        elif message_type == 19:
            body = message_dump.get("push_detail")
        elif message_type == 22:
            body = "https://www.tiktok.com/music/tiktok-{}".format(message_dump.get("music_id"))
        else:
            body= str(message_dump)
        
        return body
    