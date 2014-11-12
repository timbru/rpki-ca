package nl.bruijnzeels.tim.rpki.publication.disk

import org.scalatest.Matchers
import org.scalatest.FunSuite
import java.net.URI
import com.google.common.io.Files
import java.io.File

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ObjectDiskWriterTest extends FunSuite with Matchers {
  
  test("write to disk") {
    
    val objectUri = URI.create("rsync://bandito.ripe.net:10873/repo/bla/2966cedd774fcc0450f98dec15ed33c1c827d381.cer")
    val baseUri = URI.create("rsync://bandito.ripe.net:10873/repo")
    
    val baseDir = Files.createTempDir
    
    val subject = new ObjectDiskWriter(baseUri, baseDir)
    
    subject.getRelativeFilePath(objectUri) should equal (Some(new File("bla/2966cedd774fcc0450f98dec15ed33c1c827d381.cer")))
    subject.getRelativeFilePath(URI.create("http://localhost/different")) should equal (None)
  }

}