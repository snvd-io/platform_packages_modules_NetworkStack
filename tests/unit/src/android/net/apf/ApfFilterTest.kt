/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package android.net.apf

import android.content.Context
import android.net.MacAddress
import android.net.apf.ApfFilter.Dependencies
import android.net.apf.BaseApfGenerator.APF_VERSION_6
import android.net.ip.IpClient.IpClientCallbacksWrapper
import androidx.test.filters.SmallTest
import com.android.internal.annotations.GuardedBy
import com.android.net.module.util.InterfaceParams
import com.android.networkstack.metrics.NetworkQuirkMetrics
import com.android.testutils.quitResources
import kotlin.test.assertEquals
import org.junit.After
import org.junit.Before
import org.mockito.ArgumentMatchers.any
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.Mockito.doAnswer
import org.mockito.MockitoAnnotations
import org.mockito.invocation.InvocationOnMock

/**
 * Test for APF filter.
 */
@SmallTest
class ApfFilterTest {
    companion object {
        private const val THREAD_QUIT_MAX_RETRY_COUNT = 3
    }

    @Mock
    private lateinit var context: Context

    @Mock private lateinit var metrics: NetworkQuirkMetrics

    @Mock private lateinit var dependencies: Dependencies

    @Mock private lateinit var ipClientCallback: IpClientCallbacksWrapper

    @GuardedBy("mApfFilterCreated")
    private val mApfFilterCreated = ArrayList<AndroidPacketFilter>()
    private val loInterfaceParams = InterfaceParams.getByName("lo")
    private val ifParams =
        InterfaceParams(
            "lo",
            loInterfaceParams.index,
            MacAddress.fromBytes(byteArrayOf(2, 3, 4, 5, 6, 7)),
            loInterfaceParams.defaultMtu
        )

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)
        doAnswer { invocation: InvocationOnMock ->
            synchronized(mApfFilterCreated) {
                mApfFilterCreated.add(invocation.getArgument(0))
            }
        }.`when`(dependencies).onApfFilterCreated(any())
    }

    private fun shutdownApfFilters() {
        quitResources(THREAD_QUIT_MAX_RETRY_COUNT, {
            synchronized(mApfFilterCreated) {
                val ret = ArrayList(mApfFilterCreated)
                mApfFilterCreated.clear()
                return@quitResources ret
            }
        }, { apf: AndroidPacketFilter ->
            apf.shutdown()
        })

        synchronized(mApfFilterCreated) {
            assertEquals(
                0,
                mApfFilterCreated.size.toLong(),
                "ApfFilters did not fully shutdown."
            )
        }
    }

    @After
    fun tearDown() {
        shutdownApfFilters()
        Mockito.framework().clearInlineMocks()
        ApfJniUtils.resetTransmittedPacketMemory()
    }

    private fun getDefaultConfig(apfVersion: Int = APF_VERSION_6): ApfFilter.ApfConfiguration {
        val config = ApfFilter.ApfConfiguration()
        config.apfVersionSupported = apfVersion
        // 4K is the highly recommended value in APFv6 for vendor
        config.apfRamSize = 4096
        config.multicastFilter = false
        config.ieee802_3Filter = false
        config.ethTypeBlackList = IntArray(0)
        config.shouldHandleArpOffload = true
        config.shouldHandleNdOffload = true
        return config
    }

    private fun getApfFilter(
        apfCfg: ApfFilter.ApfConfiguration = getDefaultConfig(APF_VERSION_6)
    ): ApfFilter {
        return ApfFilter(
            context,
            apfCfg,
            ifParams,
            ipClientCallback,
            metrics,
            dependencies
        )
    }
}
