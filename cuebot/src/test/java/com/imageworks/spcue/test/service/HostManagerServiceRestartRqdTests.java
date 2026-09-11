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

package com.imageworks.spcue.test.service;

import org.junit.Before;
import org.junit.Test;

import com.imageworks.spcue.HostEntity;
import com.imageworks.spcue.HostInterface;
import com.imageworks.spcue.dao.HostDao;
import com.imageworks.spcue.grpc.host.HardwareState;
import com.imageworks.spcue.rqd.RqdClient;
import com.imageworks.spcue.rqd.RqdClientException;
import com.imageworks.spcue.service.HostManagerService;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the RQD service restart contract of {@link HostManagerService}: restarts are
 * refused unless the host is UP (protecting pending reboots and repair holds from being clobbered
 * by the restart's boot report), RQD-side failures propagate instead of reporting silent success,
 * and the drain state is written only after RQD accepted the request.
 */
public class HostManagerServiceRestartRqdTests {

    private HostManagerService hostManager;
    private HostDao hostDao;
    private RqdClient rqdClient;
    private HostInterface host;

    @Before
    public void setUp() {
        hostManager = new HostManagerService();
        hostDao = mock(HostDao.class);
        rqdClient = mock(RqdClient.class);
        hostManager.setHostDao(hostDao);
        hostManager.setRqdClient(rqdClient);

        HostEntity hostEntity = new HostEntity();
        hostEntity.id = "host-id";
        hostEntity.name = "test-host";
        host = hostEntity;
    }

    @Test
    public void restartRqdNowSetsRebootingStateAfterRqdAccepts() {
        when(hostDao.isHostUp(host)).thenReturn(true);

        hostManager.restartRqdNow(host);

        verify(rqdClient).restartRqdNow(host);
        verify(hostDao).updateHostState(host, HardwareState.REBOOTING);
    }

    @Test
    public void restartRqdWhenIdleSetsRebootWhenIdleStateAfterRqdAccepts() {
        when(hostDao.isHostUp(host)).thenReturn(true);

        hostManager.restartRqdWhenIdle(host);

        verify(rqdClient).restartRqdWhenIdle(host);
        verify(hostDao).updateHostState(host, HardwareState.REBOOT_WHEN_IDLE);
    }

    @Test
    public void restartRqdNowRefusesWhenHostIsNotUp() {
        when(hostDao.isHostUp(host)).thenReturn(false);

        assertThrows(IllegalStateException.class, () -> hostManager.restartRqdNow(host));

        verify(rqdClient, never()).restartRqdNow(any());
        verify(hostDao, never()).updateHostState(any(), any());
    }

    @Test
    public void restartRqdWhenIdleRefusesWhenHostIsNotUp() {
        when(hostDao.isHostUp(host)).thenReturn(false);

        assertThrows(IllegalStateException.class, () -> hostManager.restartRqdWhenIdle(host));

        verify(rqdClient, never()).restartRqdWhenIdle(any());
        verify(hostDao, never()).updateHostState(any(), any());
    }

    @Test
    public void restartRqdNowPropagatesRqdFailureWithoutTouchingHostState() {
        when(hostDao.isHostUp(host)).thenReturn(true);
        doThrow(new RqdClientException("rqd unreachable")).when(rqdClient).restartRqdNow(host);

        assertThrows(RqdClientException.class, () -> hostManager.restartRqdNow(host));

        verify(hostDao, never()).updateHostState(any(), any());
    }

    @Test
    public void restartRqdWhenIdlePropagatesRqdFailureWithoutTouchingHostState() {
        when(hostDao.isHostUp(host)).thenReturn(true);
        doThrow(new RqdClientException("not supported")).when(rqdClient).restartRqdWhenIdle(host);

        assertThrows(RqdClientException.class, () -> hostManager.restartRqdWhenIdle(host));

        verify(hostDao, never()).updateHostState(any(), any());
    }
}
