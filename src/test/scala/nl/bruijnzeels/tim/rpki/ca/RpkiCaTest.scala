package nl.bruijnzeels.tim.rpki.ca

import org.scalatest.Matchers
import org.scalatest.FunSuite
import org.scalatest.BeforeAndAfter
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventStore

/**
 * Base class for testing. Wipes the EventStore. Do NOT run tests that rely on this in paralel.
 */
abstract class RpkiCaTest extends FunSuite with Matchers with BeforeAndAfter {

  before {
    EventStore.clear
  }

}