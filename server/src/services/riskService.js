const { evaluateContextualDecision } = require('./decisionEngine');

/**
 * Risk & Security Context Evaluation Wrapper
 * Delegates to decisionEngine.js for explainable decision matrix evaluation.
 */

async function evaluateRisk(userId, req, operationType, sensitivityLevel = 'NORMAL') {
  return await evaluateContextualDecision(userId, req, operationType, sensitivityLevel);
}

module.exports = {
  evaluateRisk,
};
