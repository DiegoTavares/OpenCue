
/*
 * Copyright Contributors to the OpenCue Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.imageworks.spcue;

public class GroupDetail extends Entity implements GroupInterface, DepartmentInterface {

    public int jobMinCores = -1;
    public int jobMaxCores = -1;
    public int jobMinGpus = -1;
    public int jobMaxGpus = -1;
    public int jobPriority = -1;

    public int minCores = -1;
    public int maxCores = -1;

    public int minGpus = -1;
    public int maxGpus = -1;

    public String parentId = null;
    public String showId;
    public String deptId;

    @Override
    public String getShowId() {
        return showId;
    }

    public String getGroupId() {
        return id;
    }

    @Override
    public String getDepartmentId() {
        return deptId;
    }
}
