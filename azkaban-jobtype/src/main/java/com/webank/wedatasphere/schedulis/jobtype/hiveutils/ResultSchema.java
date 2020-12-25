/*
 * Copyright 2020 WeBank
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webank.wedatasphere.schedulis.jobtype.hiveutils;

/**
 * Simple class to represent the resulting schema of a Hive query, which may or
 * may not have been run. We use this simple version of the results rather than
 * exposing Hive's internal classes in order to avoid tying end users to any
 * particular version of Hive or its classes.
 */
public class ResultSchema {
  final String name;
  final String type;
  final String comment;

  public ResultSchema(String name, String type, String comment) {
    this.name = name;
    this.type = type;
    this.comment = comment;
  }

  public String getComment() {
    return comment;
  }

  public String getName() {
    return name;
  }

  public String getType() {
    return type;
  }

}
