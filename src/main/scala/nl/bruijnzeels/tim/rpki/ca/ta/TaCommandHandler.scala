package nl.bruijnzeels.tim.rpki.ca.ta

sealed trait TaCommandHandler[C <: TaCommand] {
  def handle(taCommand: C): List[TaEvent]
}

object CreateTaCommandHandler extends TaCommandHandler[CreateTa] {
  override def handle(command: CreateTa) = {
    TrustAnchor.create(command.name)
               .updateResources(command.resources)
               .createKey
               .events
  }
}
