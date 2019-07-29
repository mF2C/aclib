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
#ENV CALIB_IP="127.0.0.1"
# Port number for the CA Lib TCP server
ENV CALIB_PORT="46080"
# Port number for the local CAU-Client
ENV CAUCLIENT_PORT="46065"
# create working folder
RUN mkdir /var/app/calib
#for sharing owner Agent's certificate and key 
RUN mkdir /pkidata
VOLUME /pkidata
# copy jar to working lib
ADD mf2c-aclib-jar-with-dependencies.jar /var/app/calib/mf2c-aclib.jar
WORKDIR /var/app/calib
# Default port used for CA-LIB
EXPOSE ${CALIB_PORT}
#run the application
CMD exec java -jar mf2c-aclib.jar ${CALIB_PORT} ${CAUCLIENT_PORT}

