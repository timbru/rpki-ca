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