
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

import com.imageworks.spcue.dispatcher.ResourceContainer;
import com.imageworks.spcue.grpc.host.HardwareState;
import com.imageworks.spcue.grpc.host.LockState;
import com.imageworks.spcue.util.CueUtil;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

public class DispatchHost extends Entity
        implements HostInterface, FacilityInterface, ResourceContainer {

    private static final Logger logger = LogManager.getLogger(DispatchHost.class);

    public String facilityId;
    public String allocationId;
    public LockState lockState;
    public HardwareState hardwareState;

    public int cores;
    public int idleCores;

    public int gpus;
    public int idleGpus;

    // Basically an 0 = auto, 1 = all.
    public int threadMode;

    public long memory;
    public long idleMemory;
    public long gpuMemory;
    public long idleGpuMemory;
    public String tags;
    private String os;

    public boolean isNimby;
    public boolean isLocalDispatch = false;

    /**
     * Number of cores that will be added to the first proc booked to this host.
     */
    public int strandedCores = 0;
    public int strandedGpus = 0;

    // To reserve resources for future gpu job
    long idleMemoryOrig = 0;
    int idleCoresOrig = 0;
    long idleGpuMemoryOrig = 0;
    int idleGpusOrig = 0;

    public String getHostId() {
        return id;
    }

    public String getAllocationId() {
        return allocationId;
    }

    public String getFacilityId() {
        return facilityId;
    }

    public String[] getOs() {
        return this.os.split(",");
    }

    public void setOs(String os) {
        this.os = os;
    }

    public boolean canHandleNegativeCoresRequest(int requestedCores) {
        // Request is positive, no need to test further.
        if (requestedCores > 0) {
            logger.debug(getName() + " can handle the job with " + requestedCores + " cores.");
            return true;
        }
        // All cores are available, validate the request.
        if (cores == idleCores) {
            logger.debug(getName() + " can handle the job with " + requestedCores + " cores.");
            return true;
        }
        // Some or all cores are busy, avoid booking again.
        logger.debug(getName() + " cannot handle the job with " + requestedCores + " cores.");
        return false;
    }

    public int handleNegativeCoresRequirement(int requestedCores) {
        // If we request a <=0 amount of cores, return positive core count.
        // Request -2 on a 24 core machine will return 22.

        if (requestedCores > 0) {
            // Do not process positive core requests.
            logger.debug("Requested " + requestedCores + " cores.");
            return requestedCores;
        }
        if (requestedCores <= 0 && idleCores < cores) {
            // If request is negative but cores are already used, return 0.
            // We don't want to overbook the host.
            logger.debug("Requested " + requestedCores
                    + " cores, but the host is busy and cannot book more jobs.");
            return 0;
        }
        // Book all cores minus the request
        int totalCores = idleCores + requestedCores;
        logger.debug("Requested " + requestedCores + " cores  <= 0, " + idleCores
                + " cores are free, booking " + totalCores + " cores");
        return totalCores;
    }

    @Override
    public boolean hasAdditionalResources(int minCores, long minMemory, int minGpus,
            long minGpuMemory) {
        minCores = handleNegativeCoresRequirement(minCores);
        if (idleCores < minCores) {
            return false;
        }
        if (minCores <= 0) {
            return false;
        } else if (idleMemory < minMemory) {
            return false;
        } else if (idleGpus < minGpus) {
            return false;
        } else if (idleGpuMemory < minGpuMemory) {
            return false;
        }

        return true;
    }

    @Override
    public void useResources(int coreUnits, long memory, int gpuUnits, long gpuMemory) {
        idleCores = idleCores - coreUnits;
        idleMemory = idleMemory - memory;
        idleGpus = idleGpus - gpuUnits;
        idleGpuMemory = idleGpuMemory - gpuMemory;
    }

    /**
     * If host has idle gpu, remove enough resources to book a gpu frame later.
     *
     */
    public void removeGpu() {
        if (idleGpuMemory > 0 && idleGpuMemoryOrig == 0) {
            idleMemoryOrig = idleMemory;
            idleCoresOrig = idleCores;
            idleGpuMemoryOrig = idleGpuMemory;
            idleGpusOrig = idleGpus;

            idleMemory = idleMemory - Math.min(CueUtil.GB4, idleMemory);
            idleCores = idleCores - Math.min(100, idleCores);
            idleGpuMemory = idleGpuMemory - Math.min(CueUtil.GB4, idleGpuMemory);
            idleGpus = idleGpus - Math.min(1, idleGpus);
        }
    }

    /**
     * If host had idle gpu removed, restore the host to the origional state.
     *
     */
    public void restoreGpu() {
        if (idleGpuMemoryOrig > 0) {
            idleMemory = idleMemoryOrig;
            idleCores = idleCoresOrig;
            idleGpuMemory = idleGpuMemoryOrig;
            idleGpus = idleGpusOrig;

            idleMemoryOrig = 0;
            idleCoresOrig = 0;
            idleGpuMemoryOrig = 0;
            idleGpusOrig = 0;
        }
    }
}
