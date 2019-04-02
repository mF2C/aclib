#############################################################################
# Copyright 2018-20 UKRI Science and Technology Facilities Council
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License 
#############################################################################
#use apline base image, Oracle one has problem with licence
FROM openjdk:8-jdk-alpine
#
LABEL author="Shirley Crompton" \
      vendor="UK RI STFC" \
      eu.mf2c-project.version="1.0" \
      eu.mf2c-project.version.is-production="false" 
#
# IP for the CA Lib TCP server
ENV CALIB_IP="127.0.0.1"
# Port number for the CA Lib TCP server
ENV CALIB_PORT="46080"
# Port number for the local CAU-Client
ENV CAUCLIENT_PORT= "46065"
# create working folder
RUN mkdir /var/app
#for sharing owner Agent's certificate and key 
RUN mkdir /pkidata
VOLUME /pkidata
# copy jar to working lib
ADD ca-lib.jar /var/app/ca-lib.jar
WORKDIR /var/app
# Default port used for CA-LIB
EXPOSE 46080
#run the application
CMD exec java -jar ca-lib.jar ${CALIB_IP} ${CALIB_PORT} ${CAUCLIENT_PORT}

