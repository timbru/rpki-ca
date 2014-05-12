package nl.bruijnzeels.tim.rpki.ca.ta

import  org.scalatest.Matchers
import org.scalatest.FunSuite

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class CreateTaCommandHandlerTest extends FunSuite with Matchers {
  
  test("Should initialise TA with KeyPair and self-signed certificate") {
    
    val createCommand = CreateTa("Test TA", "10/8")
    
    val events = CreateTaCommandHandler.handle(createCommand)
    
    events should have size(3)
    events(0) should equal(TaCreated("Test TA"))
    events(1) should equal(TaResourcesUpdated("10/8"))
    events(2).isInstanceOf[TaKeyPairCreated] should be (true)
  }

}
