package nl.bruijnzeels.tim.rpki.ca.ta

import  org.scalatest.Matchers
import org.scalatest.FunSuite
import net.ripe.ipresource.IpResourceSet

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class CreateTaCommandHandlerTest extends FunSuite with Matchers {
  
  test("Should initialise TA with KeyPair and self-signed certificate") {
    
    val createCommand = CreateTa("root", "10/8", "rsync://localhost/ta/root.cer", "rsync://localhost/ta/pub/")
    
    val events = CreateTaCommandHandler.handle(createCommand)
    
    events should have size(2)
    events(0) should equal(TaCreated("root"))
  }

}
