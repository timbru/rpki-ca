/**
 * Copyright (c) 2014-2015 Tim Bruijnzeels
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of this software, nor the names of its contributors, nor
 *     the names of the contributors' employers may be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package nl.bruijnzeels.tim.rpki.publication.server.store

import scala.language.postfixOps
import java.math.BigInteger
import nl.bruijnzeels.tim.rpki.ca.RpkiCaTest
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.current
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.create
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.publicationServer
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl.trustAnchor
import org.apache.commons.lang3.StringUtils
import java.nio.charset.Charset
import nl.bruijnzeels.tim.rpki.publication.messages.ReferenceHash

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class RrdpFilesStoreTest extends RpkiCaTest {

  test("Should initiate store") {
    val testBlob = "test string".getBytes(Charset.forName("UTF8"))
    val store = new RrdpFilesStore(RrdpFilesDataSources.InMemoryDataSource)

    val returnedHash = store.put(testBlob)
    returnedHash should equal(ReferenceHash.fromBytes(testBlob))
    store.retrieve(returnedHash).get should equal(testBlob)
  }

}