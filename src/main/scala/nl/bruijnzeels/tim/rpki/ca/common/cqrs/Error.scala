package nl.bruijnzeels.tim.rpki.ca.common.cqrs

trait Error {
  def reason: String
}